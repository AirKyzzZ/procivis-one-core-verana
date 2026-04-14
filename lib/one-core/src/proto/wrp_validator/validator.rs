use std::sync::Arc;

use shared_types::OrganisationId;

use super::error::WRPValidatorError;
use super::{AccessCertificateResult, RegistrationCertificateResult, WRPValidator};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::did::KeyRole;
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    TrustListSubscription, TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery,
    TrustListSubscriptionState,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::signer::registration_certificate::model::Payload;
use crate::provider::trust_list_subscriber::TrustEntityResponse;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::error::MissingProviderError;
use crate::util::access_cert_parser::{EtsiParsedAccessCert, etsi_access_cert_from_pem_chain};

pub(crate) struct WRPValidatorImpl {
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

#[async_trait::async_trait]
impl WRPValidator for WRPValidatorImpl {
    async fn validate_access_certificate_trust(
        &self,
        pem_chain: &str,
        validate_trust: Option<OrganisationId>,
    ) -> Result<AccessCertificateResult, WRPValidatorError> {
        let trust_entity = if let Some(organisation_id) = validate_trust {
            self.check_trust_management_enabled(organisation_id).await?;

            let subscriptions = self
                .get_trust_subscriptions_for_role(TrustListRoleEnum::WrpAcProvider, organisation_id)
                .await?;

            if let Some(trust_entity) = self
                .find_matching_trust_entity(subscriptions, pem_chain)
                .await?
            {
                Some(trust_entity)
            } else {
                return Err(WRPValidatorError::AccessCertificateNotTrusted);
            }
        } else {
            None
        };

        let EtsiParsedAccessCert {
            rp_id,
            registry_url,
            ..
        } = etsi_access_cert_from_pem_chain(pem_chain).error_while("parsing access certificate")?;

        Ok(AccessCertificateResult {
            trust_entity,
            rp_id,
            registry_url,
        })
    }

    async fn validate_registration_certificate(
        &self,
        wrprc_jwt: &str,
        expected_rp_id: &str,
        validate_trust: Option<OrganisationId>,
    ) -> Result<RegistrationCertificateResult, WRPValidatorError> {
        let key_verification: VerificationFn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });

        let token = Jwt::<Payload>::build_from_token(wrprc_jwt, Some(&key_verification), None)
            .await
            .error_while("parsing JWT")?;

        if token
            .payload
            .subject
            .as_ref()
            .is_none_or(|subject| subject != expected_rp_id)
        {
            return Err(WRPValidatorError::InvalidOrganisationIdentifier);
        }

        let issuer = token.header.x5c.ok_or(WRPValidatorError::MissingIssuer)?;

        let trust_entity = if let Some(organisation_id) = validate_trust {
            self.check_trust_management_enabled(organisation_id).await?;

            let issuer_chain = x5c_into_pem_chain(&issuer).error_while("converting chain")?;

            let subscriptions = self
                .get_trust_subscriptions_for_role(TrustListRoleEnum::WrpRcProvider, organisation_id)
                .await?;

            match self
                .find_matching_trust_entity(subscriptions, &issuer_chain)
                .await?
            {
                Some(trust_entity) => Some(trust_entity),
                None => {
                    return Err(WRPValidatorError::RegistrationCertificateNotTrusted);
                }
            }
        } else {
            None
        };

        Ok(RegistrationCertificateResult {
            payload: token.payload,
            trust_entity,
        })
    }
}

impl WRPValidatorImpl {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
        holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            trust_collection_repository,
            trust_list_subscription_repository,
            trust_list_subscriber_provider,
            holder_wallet_unit_repository,
            wallet_provider_client,
            did_method_provider,
            key_algorithm_provider,
            certificate_validator,
        }
    }

    async fn find_matching_trust_entity(
        &self,
        subscriptions: Vec<TrustListSubscription>,
        pem_chain: &str,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        for subscription in subscriptions {
            let subscriber = self
                .trust_list_subscriber_provider
                .get(&subscription.r#type)
                .ok_or(MissingProviderError::TrustListSubscriber(
                    subscription.r#type,
                ))
                .error_while("getting trust list subscriber")?;

            if let Some(trust_entity) = subscriber
                .resolve_certificate(&subscription.reference.parse()?, pem_chain)
                .await
                .error_while("resolving access certificate trust")?
            {
                return Ok(Some(trust_entity));
            }
        }

        Ok(None)
    }

    async fn check_trust_management_enabled(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<(), WRPValidatorError> {
        let holder_wallet_unit = self
            .holder_wallet_unit_repository
            .get_holder_wallet_unit_by_org_id(&organisation_id)
            .await
            .error_while("getting holder wallet unit")?
            // if holder wallet unit not registered, it means the trust management was not setup, thus disabled
            .ok_or(WRPValidatorError::TrustManagementDisabled)?;

        let metadata = self
            .wallet_provider_client
            .get_wallet_provider_metadata(holder_wallet_unit.into())
            .await
            .error_while("getting wallet provider metadata")?;

        if !metadata.feature_flags.trust_ecosystems_enabled {
            // trust management disabled via provider metadata
            return Err(WRPValidatorError::TrustManagementDisabled);
        }

        Ok(())
    }

    async fn get_trust_subscriptions_for_role(
        &self,
        role: TrustListRoleEnum,
        organisation_id: OrganisationId,
    ) -> Result<Vec<TrustListSubscription>, WRPValidatorError> {
        let collections = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                filtering: Some(
                    TrustCollectionFilterValue::OrganisationId(organisation_id).condition()
                        & TrustCollectionFilterValue::Remote(true)
                        & TrustCollectionFilterValue::Empty(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust collections")?
            .values
            .into_iter()
            .map(|c| c.id)
            .collect();

        Ok(self
            .trust_list_subscription_repository
            .list(TrustListSubscriptionListQuery {
                filtering: Some(
                    TrustListSubscriptionFilterValue::TrustCollectionId(collections).condition()
                        & TrustListSubscriptionFilterValue::State(vec![
                            TrustListSubscriptionState::Active,
                        ])
                        & TrustListSubscriptionFilterValue::Role(vec![role]),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust list subscriptions")?
            .values)
    }
}
