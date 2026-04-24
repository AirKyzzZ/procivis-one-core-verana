use std::borrow::Cow;
use std::sync::Arc;

use shared_types::OrganisationId;
use standardized_types::jwk::PublicJwk;
use time::Duration;
use url::Url;

use super::WRPValidator;
use super::error::WRPValidatorError;
use super::model::{
    AccessCertificateResult, FetchRegistryResult, RegistrationCertificateResult, RegistryKeys,
    WRPPayload,
};
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
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::key_verification::KeyVerification;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::credential_formatter::model::{
    CertificateDetails, CredentialStatus, IdentifierDetails, PublicKeySource, VerificationFn,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::registration_certificate::model::{Payload, Status};
use crate::provider::trust_list_subscriber::TrustEntityResponse;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::holder_wallet_instance_repository::HolderWalletInstanceRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::error::MissingProviderError;
use crate::util::access_cert_parser::{EtsiParsedAccessCert, etsi_access_cert_from_pem_chain};
use crate::validator::{validate_expiration_time, validate_not_before_time};

pub(crate) struct WRPValidatorImpl {
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    holder_wallet_unit_repository: Arc<dyn HolderWalletInstanceRepository>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    client: Arc<dyn HttpClient>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
}

#[async_trait::async_trait]
impl WRPValidator for WRPValidatorImpl {
    async fn validate_access_certificate_trust(
        &self,
        pem_chain: &str,
        validate_trust: Option<OrganisationId>,
    ) -> Result<AccessCertificateResult, WRPValidatorError> {
        let trust_entity = if let Some(organisation_id) = validate_trust {
            Some(
                self.perform_trust_validation(
                    TrustEntityIdentifier::PemChain(pem_chain),
                    TrustListRoleEnum::WrpAcProvider,
                    organisation_id,
                )
                .await?
                .ok_or(WRPValidatorError::AccessCertificateNotTrusted)?,
            )
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
            relying_party_id: rp_id,
            registry_url,
        })
    }

    async fn validate_registration_certificate(
        &self,
        wrprc_jwt: &str,
        expected_rp_id: &str,
        validate_trust: Option<OrganisationId>,
        leeway: Duration,
    ) -> Result<RegistrationCertificateResult, WRPValidatorError> {
        let token =
            Jwt::<Payload>::build_from_token(wrprc_jwt, Some(&self.verification_fn()), None)
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
        let issuer_chain = x5c_into_pem_chain(&issuer).error_while("converting chain")?;

        validate_jwt_timestamps(&token.payload, leeway)?;
        self.check_jwt_status(&token.payload.custom.status, &issuer_chain)
            .await?;

        let trust_entity = if let Some(organisation_id) = validate_trust {
            Some(
                self.perform_trust_validation(
                    TrustEntityIdentifier::PemChain(&issuer_chain),
                    TrustListRoleEnum::WrpRcProvider,
                    organisation_id,
                )
                .await?
                .ok_or(WRPValidatorError::RegistrationCertificateNotTrusted)?,
            )
        } else {
            None
        };

        Ok(RegistrationCertificateResult {
            payload: token.payload,
            trust_entity,
        })
    }

    async fn fetch_from_registry(
        &self,
        relying_party_id: &str,
        registry_url: &Url,
        validate_trust: Option<OrganisationId>,
        leeway: Duration,
    ) -> Result<FetchRegistryResult, WRPValidatorError> {
        let mut rp_url = registry_url.to_owned();
        {
            rp_url
                .path_segments_mut()
                .map_err(|_| WRPValidatorError::InvalidRegistryUrl(registry_url.to_string()))?
                .push("wrp")
                .push(relying_party_id);
        }

        let response = async {
            self.client
                .get(rp_url.as_str())
                .header("Accept", "application/jwt")
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("fetching relying party dataset")?;

        let jku_url = response
            .header_get("x-jku-url")
            .ok_or(WRPValidatorError::MissingRegistryKeysUrl)?
            .to_owned();

        let jwt = String::from_utf8(response.body)?;
        let token = Jwt::<WRPPayload>::decompose_token(&jwt).error_while("parsing JWT")?;
        validate_jwt_timestamps(&token.payload, leeway)?;

        let jwks: RegistryKeys = async {
            self.client
                .get(&jku_url)
                .header("Accept", "application/json")
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("fetching registry keys")?;

        let registry_key = jwks
            .keys
            .iter()
            .find(|key| key.kid() == token.header.key_id.as_deref())
            .ok_or(WRPValidatorError::MissingRegistryKey(
                token.header.key_id.to_owned(),
            ))?;

        token
            .verify_signature(
                PublicKeySource::Jwk {
                    jwk: Cow::Borrowed(registry_key),
                },
                &self.verification_fn(),
            )
            .await
            .error_while("verifying registry dataset signature")?;

        let trust_entity = if let Some(organisation_id) = validate_trust {
            Some(
                self.perform_trust_validation(
                    TrustEntityIdentifier::Jwk(registry_key),
                    TrustListRoleEnum::NationalRegistryRegistrar,
                    organisation_id,
                )
                .await?
                .ok_or(WRPValidatorError::RegistryNotTrusted)?,
            )
        } else {
            None
        };

        Ok(FetchRegistryResult {
            payload: token.payload,
            trust_entity,
            jwt,
        })
    }
}

enum TrustEntityIdentifier<'a> {
    PemChain(&'a str),
    Jwk(&'a PublicJwk),
}

impl WRPValidatorImpl {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
        holder_wallet_unit_repository: Arc<dyn HolderWalletInstanceRepository>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        client: Arc<dyn HttpClient>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
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
            client,
            revocation_method_provider,
        }
    }

    async fn perform_trust_validation(
        &self,
        identifier: TrustEntityIdentifier<'_>,
        role: TrustListRoleEnum,
        organisation_id: OrganisationId,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        self.check_trust_management_enabled(organisation_id).await?;

        let subscriptions = self
            .get_trust_subscriptions_for_role(role, organisation_id)
            .await?;

        self.find_matching_trust_entity(subscriptions, identifier)
            .await
    }

    async fn find_matching_trust_entity(
        &self,
        subscriptions: Vec<TrustListSubscription>,
        identifier: TrustEntityIdentifier<'_>,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError> {
        for subscription in subscriptions {
            let subscriber = self
                .trust_list_subscriber_provider
                .get(&subscription.r#type)
                .ok_or(MissingProviderError::TrustListSubscriber(
                    subscription.r#type,
                ))
                .error_while("getting trust list subscriber")?;

            let reference = subscription.reference.parse()?;
            let trust_entity = match identifier {
                TrustEntityIdentifier::PemChain(pem_chain) => {
                    subscriber.resolve_certificate(&reference, pem_chain).await
                }
                TrustEntityIdentifier::Jwk(jwk) => {
                    subscriber.resolve_public_key(&reference, jwk).await
                }
            }
            .error_while("resolving trust")?;

            if trust_entity.is_some() {
                return Ok(trust_entity);
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
            .get_holder_wallet_instance_by_org_id(&organisation_id)
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
                    TrustCollectionFilterValue::OrganisationId {
                        id: organisation_id,
                        include_inherited_collections: true,
                    }
                    .condition()
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

    async fn check_jwt_status(
        &self,
        status: &Status,
        issuer_pem_chain: &str,
    ) -> Result<(), WRPValidatorError> {
        const TOKENSTATUSLIST_ENTRY_TYPE: &str = "TokenStatusListEntry";

        let ParsedCertificate {
            attributes,
            subject_common_name,
            ..
        } = self
            .certificate_validator
            .parse_pem_chain(
                issuer_pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
            .error_while("parsing issuer certificate")?;

        let (revocation_provider, _) = self
            .revocation_method_provider
            .get_revocation_method_by_status_type(TOKENSTATUSLIST_ENTRY_TYPE)
            .ok_or(
                MissingProviderError::RevocationMethodByCredentialStatusType(
                    TOKENSTATUSLIST_ENTRY_TYPE.to_string(),
                ),
            )
            .error_while("getting revocation provider")?;

        let revocation_status = revocation_provider
            .check_credential_revocation_status(
                &CredentialStatus {
                    id: None,
                    r#type: TOKENSTATUSLIST_ENTRY_TYPE.to_string(),
                    status_purpose: None,
                    additional_fields: status.status_list.to_owned(),
                },
                &IdentifierDetails::Certificate(CertificateDetails {
                    chain: issuer_pem_chain.to_owned(),
                    fingerprint: attributes.fingerprint,
                    expiry: attributes.not_after,
                    subject_common_name,
                }),
                None,
                false,
            )
            .await
            .error_while("checking registration certificate status")?;

        match revocation_status {
            RevocationState::Valid => Ok(()),
            RevocationState::Revoked | RevocationState::Suspended { .. } => {
                Err(WRPValidatorError::CertificateRevoked)
            }
        }
    }

    fn verification_fn(&self) -> VerificationFn {
        Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        })
    }
}

fn validate_jwt_timestamps<T>(
    token: &JWTPayload<T>,
    leeway: Duration,
) -> Result<(), WRPValidatorError> {
    validate_not_before_time(&token.invalid_before, leeway).error_while("checking validity")?;
    validate_expiration_time(&token.expires_at, leeway).error_while("checking validity")?;
    Ok(())
}
