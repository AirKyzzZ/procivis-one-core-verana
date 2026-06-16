use std::str::FromStr;
use std::sync::Arc;

use futures::FutureExt;
use one_dto_mapper::convert_inner;
use shared_types::{HolderWalletInstanceId, WalletInstanceId};
use standardized_types::jwk::PublicJwk;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::WalletUnitService;
use super::dto::{
    EditHolderWalletInstanceRequestDTO, HolderActivateWalletInstanceRequestDTO,
    HolderRegisterWalletInstanceRequestDTO, HolderWalletInstanceRegisterResponseDTO,
    HolderWalletInstanceResponseDTO, NoncePayload, TrustCollectionsDetailResponseDTO,
};
use super::error::HolderWalletInstanceError;
use super::mapper::{key_from_generated_key, prepare_trust_collection_info};
use crate::config::core_config::{KeyAlgorithmType, KeyStorageType};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::holder_wallet_instance::HolderWalletInstanceFilterValue::OrganisationIds;
use crate::model::holder_wallet_instance::{
    CreateHolderWalletInstanceRequest, HolderWalletInstanceRelations,
    UpdateHolderWalletInstanceRequest,
};
use crate::model::key::{Key, KeyRelations};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::organisation::Organisation;
use crate::model::wallet_instance::{WalletInstanceOs, WalletInstanceStatus};
use crate::model::wallet_instance_attestation::WalletInstanceAttestationRelations;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::proto::session_provider::SessionExt;
use crate::proto::wallet_instance::WalletUnitStatusCheckResponse;
use crate::proto::wallet_provider_client::dto::MetadataTarget;
use crate::proto::wallet_provider_client::error::WalletProviderClientError;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::repository::error::DataLayerError;
use crate::service::error::MissingProviderError;
use crate::service::wallet_instance::mapper::set_active_trust_collections;
use crate::service::wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO,
    WalletProviderMetadataResponseDTO,
};
use crate::validator::throw_if_org_id_not_matching_session;

impl WalletUnitService {
    pub async fn holder_register(
        &self,
        request: HolderRegisterWalletInstanceRequestDTO,
    ) -> Result<HolderWalletInstanceRegisterResponseDTO, HolderWalletInstanceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?
            .ok_or(HolderWalletInstanceError::MissingOrganisation(
                request.organisation_id,
            ))?;

        if organisation.deactivated_at.is_some() {
            return Err(HolderWalletInstanceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        if let Some(wallet_unit) = self
            .holder_wallet_instance_repository
            .list(ListQuery {
                filtering: Some(OrganisationIds(vec![request.organisation_id]).condition()),
                ..Default::default()
            })
            .await
            .error_while("checking presence of wallet instance")?
            .values
            .into_iter()
            .next()
        {
            if wallet_unit.status != WalletInstanceStatus::Error {
                return Err(HolderWalletInstanceError::WalletInstanceAlreadyExists(
                    wallet_unit.id,
                ));
            }
            // A failed (Error) wallet unit is left behind when registration is aborted (e.g.
            // expired nonce). Remove it so the holder can restart registration (an organisation
            // may only have a single wallet unit).
            self.holder_wallet_instance_repository
                .delete(&wallet_unit.id)
                .await
                .error_while("deleting failed wallet instance")?;
        }

        let (os, key_storage_id) = self.resolve_os_and_key_storage().await?;
        let key_type = self.parse_and_validate_key_type(&request.key_type)?;

        let wallet_provider_url = Url::from_str(&request.wallet_provider.url)
            .map_err(HolderWalletInstanceError::InvalidWalletProviderUrl)?
            .origin()
            .ascii_serialization();
        let metadata = self
            .wallet_provider_client
            .get_wallet_provider_metadata(request.wallet_provider.to_owned().into())
            .await
            .error_while("getting wallet provider metadata")?;
        let provider_info = WalletProviderInfo {
            name: metadata.name.clone(),
            url: wallet_provider_url.clone(),
        };

        let is_integrity_check_required = metadata
            .wallet_unit_attestation
            .app_integrity_check_required
            && os != WalletInstanceOs::Web;
        let is_authentication_required = metadata.user_authentication.is_some();

        let registration_status = match (is_authentication_required, is_integrity_check_required) {
            (true, true) => {
                self.register_pending_integrity_check(&provider_info, os)
                    .await?
            }
            (true, false) => {
                self.register_pending_no_integrity_check(
                    &provider_info,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                )
                .await?
            }
            (false, true) => {
                self.register_and_activate_with_integrity_check(
                    &provider_info,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                )
                .await?
            }
            (false, false) => {
                self.register_active(
                    &provider_info,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                )
                .await?
            }
        };

        let wallet_instance_request = registration_status.map_to_create_wallet_instance_request(
            &request,
            &organisation,
            wallet_provider_url,
            &metadata,
        );
        let user_nonce = wallet_instance_request.user_nonce.clone();
        let status = wallet_instance_request.status;

        let holder_wallet_unit_id = self
            .holder_wallet_instance_repository
            .create(wallet_instance_request)
            .await
            .error_while("creating holder wallet unit")?;

        let now = self.clock.now_utc();
        let wallet_unit_name = format!(
            "{}-{}-{}",
            request.wallet_provider.r#type,
            os,
            now.unix_timestamp()
        );
        let success_log = format!(
            "Registered wallet unit `{wallet_unit_name}`({holder_wallet_unit_id}) using wallet provider `{}`, with status {status}",
            request.wallet_provider.url
        );
        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now,
                action: HistoryAction::Created,
                name: wallet_unit_name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(holder_wallet_unit_id.into()),
                entity_type: HistoryEntityType::WalletUnit,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(organisation.id),
                user: self.session_provider.session().user(),
            })
            .await
            .error_while("creating history")?;

        self.trust_collection_manager
            .create_empty_trust_collections(
                &request.wallet_provider.url,
                convert_inner(metadata.trust_collections),
                organisation.id,
            )
            .await
            .error_while("creating empty trust collections")?;

        tracing::info!(message = success_log);
        Ok(HolderWalletInstanceRegisterResponseDTO {
            id: holder_wallet_unit_id,
            status,
            user_nonce,
        })
    }

    pub async fn holder_activate(
        &self,
        id: HolderWalletInstanceId,
        request: HolderActivateWalletInstanceRequestDTO,
    ) -> Result<(), HolderWalletInstanceError> {
        let holder_wallet_instance = self
            .holder_wallet_instance_repository
            .get(&id, &HolderWalletInstanceRelations::default())
            .await
            .error_while("getting holder wallet instance")?
            .ok_or(HolderWalletInstanceError::HolderWalletUnitNotFound(id))?;

        let organisation_id = holder_wallet_instance.organisation.id();
        throw_if_org_id_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("checking session")?;

        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id)
            .await
            .error_while("getting organisation")?
            .ok_or(HolderWalletInstanceError::MissingOrganisation(
                organisation_id,
            ))?;

        if holder_wallet_instance.status != WalletInstanceStatus::Pending {
            return Err(HolderWalletInstanceError::WalletUnitNotPending);
        }

        let metadata = self
            .wallet_provider_client
            .get_wallet_provider_metadata(MetadataTarget {
                r#type: holder_wallet_instance.wallet_provider_type,
                metadata_url: format!(
                    "{}/ssi/wallet-provider/v1/{}",
                    holder_wallet_instance.wallet_provider_url,
                    holder_wallet_instance.wallet_provider_name
                ),
            })
            .await
            .error_while("getting wallet provider metadata")?;

        let Some(user_authentication) = metadata.user_authentication else {
            return Err(HolderWalletInstanceError::UserAuthenticationNotConfigured);
        };

        // The id token is optional at activate. Fail early (without calling the wallet provider)
        // only when authentication is required but no token was supplied.
        let user_id_token = match request.user_id_token {
            Some(token) => Some(token),
            None if user_authentication.required => {
                return Err(HolderWalletInstanceError::UserAuthenticationRequired);
            }
            None => None,
        };

        let activation_status = if let Some(nonce) = holder_wallet_instance.nonce {
            let (os, key_storage_id) = self.resolve_os_and_key_storage().await?;
            let key_type = self.parse_and_validate_key_type(&request.key_type)?;

            let provider_info = WalletProviderInfo {
                name: holder_wallet_instance.wallet_provider_name.clone(),
                url: holder_wallet_instance.wallet_provider_url.clone(),
            };

            match self
                .activate_with_integrity_check(
                    &provider_info,
                    key_storage_id,
                    key_type,
                    os,
                    organisation.clone(),
                    holder_wallet_instance.provider_wallet_unit_id,
                    nonce,
                    user_id_token,
                )
                .await
            {
                Ok(RegistrationStatus::Active { key, .. }) => {
                    Ok((WalletInstanceStatus::Active, Some(key.id)))
                }
                Ok(
                    RegistrationStatus::PendingNoIntegrityCheck { .. }
                    | RegistrationStatus::PendingIntegrityCheck { .. }
                    | RegistrationStatus::Unattested { .. },
                ) => Ok((WalletInstanceStatus::Unattested, None)),
                Err(err) => Err(err),
            }
        } else {
            let activate_request = ActivateWalletUnitRequestDTO {
                attestation: None,
                attestation_key_proof: None,
                device_signing_key_proof: None,
                user_id_token,
            };

            match self
                .wallet_provider_client
                .activate(
                    &holder_wallet_instance.wallet_provider_url,
                    holder_wallet_instance.provider_wallet_unit_id,
                    activate_request,
                )
                .await
            {
                Ok(_) => Ok((WalletInstanceStatus::Active, None)),
                Err(WalletProviderClientError::WalletUnitNonceExpired) => {
                    Err(HolderWalletInstanceError::WalletUnitRegistrationExpired)
                }
                Err(err) if err.error_code() == ErrorCode::BR_0395 => {
                    tracing::warn!("Activation request failed: {err}");
                    Ok((WalletInstanceStatus::Unattested, None))
                }
                Err(err) => Err(err.error_while("activating wallet unit").into()),
            }
        };

        let (status, authentication_key_id) = match activation_status {
            Err(HolderWalletInstanceError::WalletUnitRegistrationExpired) => {
                // The registration nonce has expired. Mark the instance failed (out of PENDING)
                // so the wallet restarts registration from scratch instead of re-activating
                // against the dead nonce.
                self.holder_wallet_instance_repository
                    .update(
                        &id,
                        UpdateHolderWalletInstanceRequest {
                            status: Some(WalletInstanceStatus::Error),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("marking holder wallet instance failed")?;
                return Err(HolderWalletInstanceError::WalletUnitRegistrationExpired);
            }
            other => other.error_while("activating wallet unit")?,
        };

        self.holder_wallet_instance_repository
            .update(
                &id,
                UpdateHolderWalletInstanceRequest {
                    status: Some(status),
                    authentication_key_id,
                    ..Default::default()
                },
            )
            .await
            .error_while("updating holder wallet instance status")?;

        Ok(())
    }

    async fn generate_attestation_key(
        &self,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        nonce: Option<String>,
    ) -> Result<Option<Key>, HolderWalletInstanceError> {
        let key_storage = self.key_provider.get_key_storage(key_storage_id)?;

        let key_id = Uuid::new_v4().into();
        let attestation_key = match key_storage.generate_attestation_key(key_id, nonce).await {
            Ok(key) => key,
            Err(KeyStorageError::NotSupported(description)) => {
                tracing::info!("Attestation keys not supported: {description}");
                return Ok(None);
            }
            Err(err) => return Err(err.error_while("getting attestation key").into()),
        };
        let attestation_key = key_from_generated_key(
            key_id,
            key_storage_id,
            key_type.as_ref(),
            organisation,
            attestation_key,
        );
        self.store_key(&attestation_key).await?;
        Ok(Some(attestation_key))
    }

    pub async fn holder_get_wallet_unit_details(
        &self,
        id: HolderWalletInstanceId,
    ) -> Result<HolderWalletInstanceResponseDTO, HolderWalletInstanceError> {
        let result = self
            .holder_wallet_instance_repository
            .get(
                &id,
                &HolderWalletInstanceRelations {
                    authentication_key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting holder wallet unit")?
            .ok_or(HolderWalletInstanceError::HolderWalletUnitNotFound(id))?;

        Ok(result.into())
    }

    pub async fn holder_get_wallet_unit_trust_collections(
        &self,
        id: HolderWalletInstanceId,
    ) -> Result<TrustCollectionsDetailResponseDTO, HolderWalletInstanceError> {
        let unit = self
            .holder_wallet_instance_repository
            .get(&id, &HolderWalletInstanceRelations::default())
            .await
            .error_while("getting holder wallet unit")?
            .ok_or(HolderWalletInstanceError::HolderWalletUnitNotFound(id))?;

        let organisation_id = unit.organisation.id();

        throw_if_org_id_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("checking session")?;

        let metadata = self
            .wallet_provider_client
            .get_wallet_provider_metadata(unit.into())
            .await
            .error_while("getting wallet provider metadata")?;

        let trust_collections = prepare_trust_collection_info(
            self.trust_collection_repository.as_ref(),
            self.trust_subscription_repository.as_ref(),
            metadata.trust_collections,
            organisation_id,
        )
        .await?;

        Ok(TrustCollectionsDetailResponseDTO { trust_collections })
    }

    pub async fn holder_wallet_unit_status(
        &self,
        id: HolderWalletInstanceId,
    ) -> Result<(), HolderWalletInstanceError> {
        let holder_wallet_unit = self
            .holder_wallet_instance_repository
            .get(
                &id,
                &HolderWalletInstanceRelations {
                    authentication_key: Some(KeyRelations::default()),
                    wallet_unit_attestations: Some(WalletInstanceAttestationRelations::default()),
                },
            )
            .await
            .error_while("getting holder wallet unit")?
            .ok_or(HolderWalletInstanceError::HolderWalletUnitNotFound(id))?;

        if holder_wallet_unit.status != WalletInstanceStatus::Active {
            return Ok(());
        }

        let wallet_unit_status = self
            .wallet_unit_proto
            .check_wallet_unit_status(&holder_wallet_unit)
            .await
            .error_while("checking wallet unit status")?;

        if wallet_unit_status == WalletUnitStatusCheckResponse::Revoked {
            self.holder_wallet_instance_repository
                .update(
                    &id,
                    UpdateHolderWalletInstanceRequest {
                        status: Some(WalletInstanceStatus::Revoked),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating holder wallet unit")?;

            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    action: HistoryAction::Revoked,
                    name: holder_wallet_unit.wallet_provider_name.clone(),
                    source: HistorySource::Core,
                    target: None,
                    entity_id: Some(id.into()),
                    entity_type: HistoryEntityType::WalletUnit,
                    metadata: None,
                    metadata_blob_id: None,
                    organisation_id: Some(holder_wallet_unit.organisation.id()),
                    user: self.session_provider.session().user(),
                    created_date: self.clock.now_utc(),
                })
                .await
                .error_while("creating history")?;
        }
        Ok(())
    }

    pub async fn edit_holder_wallet_unit(
        &self,
        id: HolderWalletInstanceId,
        request: EditHolderWalletInstanceRequestDTO,
    ) -> Result<(), HolderWalletInstanceError> {
        let holder_wallet_instance = self
            .holder_wallet_instance_repository
            .get(&id, &HolderWalletInstanceRelations::default())
            .await
            .error_while("getting holder wallet unit")?
            .ok_or(HolderWalletInstanceError::HolderWalletUnitNotFound(id))?;

        let organisation = holder_wallet_instance.organisation.as_ref().await?;

        throw_if_org_id_not_matching_session(&organisation.id, &*self.session_provider)
            .error_while("checking session")?;

        self.tx_manager
            .tx(async {
                if let Some(trusted_rp_required) = request.trusted_rp_required
                    && trusted_rp_required != holder_wallet_instance.trusted_rp_required
                {
                    self.holder_wallet_instance_repository
                        .update(
                            &id,
                            UpdateHolderWalletInstanceRequest {
                                trusted_rp_required: Some(trusted_rp_required),
                                ..Default::default()
                            },
                        )
                        .await
                        .error_while("updating trusted_rp_required")?;
                }
                if let Some(trust_collections) = request.trust_collections {
                    set_active_trust_collections(
                        trust_collections,
                        organisation.id,
                        self.trust_collection_repository.as_ref(),
                        self.trust_subscription_repository.as_ref(),
                        self.trust_list_subscription_sync.as_ref(),
                    )
                    .await
                    .error_while("updating collections")?;
                };
                Ok::<_, HolderWalletInstanceError>(())
            }
            .boxed())
            .await
            .error_while("updating holder wallet instance")??;

        tracing::info!("Modified holder wallet unit ({id})");
        Ok(())
    }

    /// Authentication required, integrity check required: register without a key (the attestation
    /// key is generated during activation) and store both nonces. Stays pending until activation.
    async fn register_pending_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        os: WalletInstanceOs,
    ) -> Result<RegistrationStatus, HolderWalletInstanceError> {
        let register_response = self
            .register(
                &provider_info.url,
                RegisterWalletUnitRequestDTO {
                    wallet_provider: provider_info.name.clone(),
                    os,
                    public_key: None,
                    proof: None,
                },
            )
            .await
            .error_while("registering")?;
        let Some(user_nonce) = register_response.user_nonce else {
            // authentication check was expected but is not required
            return Err(HolderWalletInstanceError::UserAuthenticationNotRequired);
        };
        let Some(nonce) = register_response.nonce else {
            // integrity check was expected but is not required
            return Err(HolderWalletInstanceError::AppIntegrityCheckNotRequired);
        };
        Ok(RegistrationStatus::PendingIntegrityCheck {
            wallet_instance_id: register_response.id,
            user_nonce,
            nonce,
        })
    }

    /// Authentication required, no integrity check: register with a key right away and store the
    /// user nonce. Stays pending until the user authenticates during activation.
    async fn register_pending_no_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletInstanceOs,
        organisation: Organisation,
    ) -> Result<RegistrationStatus, HolderWalletInstanceError> {
        let (key, register_response) = self
            .register_without_integrity_check(
                provider_info,
                key_storage_id,
                key_type,
                os,
                organisation,
            )
            .await?;
        let Some(user_nonce) = register_response.user_nonce else {
            // authentication check was expected but is not required
            return Err(HolderWalletInstanceError::UserAuthenticationNotRequired);
        };
        if register_response.nonce.is_some() {
            // integrity check was not expected but is required
            return Err(HolderWalletInstanceError::AppIntegrityCheckRequired);
        }
        Ok(RegistrationStatus::PendingNoIntegrityCheck {
            wallet_instance_id: register_response.id,
            user_nonce,
            key,
        })
    }

    /// No authentication, integrity check required: register without a key, then activate
    /// immediately with the attestation (no user token).
    async fn register_and_activate_with_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletInstanceOs,
        organisation: Organisation,
    ) -> Result<RegistrationStatus, HolderWalletInstanceError> {
        let register_response = self
            .register(
                &provider_info.url,
                RegisterWalletUnitRequestDTO {
                    wallet_provider: provider_info.name.clone(),
                    os,
                    public_key: None,
                    proof: None,
                },
            )
            .await
            .error_while("registering")?;
        if register_response.user_nonce.is_some() {
            // authentication was not expected but is required
            return Err(HolderWalletInstanceError::UserAuthenticationRequired);
        }
        let Some(nonce) = register_response.nonce else {
            // integrity check was expected but is not required
            return Err(HolderWalletInstanceError::AppIntegrityCheckNotRequired);
        };
        self.activate_with_integrity_check(
            provider_info,
            key_storage_id,
            key_type,
            os,
            organisation,
            register_response.id,
            nonce,
            None,
        )
        .await
    }

    /// No authentication, no integrity check: register with a key and activate in a single step.
    async fn register_active(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletInstanceOs,
        organisation: Organisation,
    ) -> Result<RegistrationStatus, HolderWalletInstanceError> {
        let (key, register_response) = self
            .register_without_integrity_check(
                provider_info,
                key_storage_id,
                key_type,
                os,
                organisation,
            )
            .await?;
        if register_response.user_nonce.is_some() {
            // authentication was not expected but is required
            return Err(HolderWalletInstanceError::UserAuthenticationRequired);
        }
        if register_response.nonce.is_some() {
            // integrity check was not expected but is required
            return Err(HolderWalletInstanceError::AppIntegrityCheckRequired);
        }
        Ok(RegistrationStatus::Active {
            wallet_instance_id: register_response.id,
            key,
        })
    }

    async fn register_without_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletInstanceOs,
        organisation: Organisation,
    ) -> Result<(Key, RegisterWalletUnitResponseDTO), HolderWalletInstanceError> {
        let (key, signed_proof) = self
            .generate_key_and_proof(key_storage_id, key_type, organisation, provider_info, None)
            .await?;

        let key_storage = self.key_provider.get_key_storage(key_storage_id)?;
        let key_handle = key_storage
            .key_handle(&key)
            .error_while("getting key handle")?;

        let register_request = RegisterWalletUnitRequestDTO {
            wallet_provider: provider_info.name.clone(),
            os,
            public_key: Some(key_handle.public_key_as_jwk().error_while("creating JWK")?),
            proof: Some(signed_proof),
        };

        let response = self
            .register(&provider_info.url, register_request)
            .await
            .error_while("registering")?;
        Ok((key, response))
    }

    #[allow(clippy::too_many_arguments)]
    async fn activate_with_integrity_check(
        &self,
        provider_info: &WalletProviderInfo,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        os: WalletInstanceOs,
        organisation: Organisation,
        wallet_instance_id: WalletInstanceId,
        nonce: String,
        user_id_token: Option<String>,
    ) -> Result<RegistrationStatus, HolderWalletInstanceError> {
        let attestations_key = self
            .generate_attestation_key(
                key_storage_id,
                key_type,
                organisation.clone(),
                Some(nonce.clone()),
            )
            .await?;

        let proofs = if let Some(attestations_key) = attestations_key {
            self.build_attestation_proofs(
                attestations_key,
                key_storage_id,
                key_type,
                organisation,
                provider_info,
                Some(nonce),
                os,
            )
            .await?
        } else {
            return Ok(RegistrationStatus::Unattested { wallet_instance_id });
        };

        let activate_request = ActivateWalletUnitRequestDTO {
            attestation: Some(proofs.attestation),
            attestation_key_proof: Some(proofs.attestation_key_proof),
            device_signing_key_proof: proofs.device_sig_pop,
            user_id_token,
        };

        match self
            .wallet_provider_client
            .activate(&provider_info.url, wallet_instance_id, activate_request)
            .await
        {
            Ok(_) => {}
            Err(WalletProviderClientError::WalletUnitNonceExpired) => {
                return Err(HolderWalletInstanceError::WalletUnitRegistrationExpired);
            }
            Err(err) if err.error_code() == ErrorCode::BR_0395 => {
                tracing::warn!("Activation request failed: {err}");
                return Ok(RegistrationStatus::Unattested { wallet_instance_id });
            }
            Err(err) => return Err(err.error_while("activating wallet unit").into()),
        };

        Ok(RegistrationStatus::Active {
            wallet_instance_id,
            key: proofs.key,
        })
    }

    async fn new_key(
        &self,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        key_storage: &Arc<dyn KeyStorage>,
    ) -> Result<Key, HolderWalletInstanceError> {
        let key_id = Uuid::new_v4().into();
        let key = key_storage
            .generate(key_id, key_type)
            .await
            .error_while("generating key")?;
        let key =
            key_from_generated_key(key_id, key_storage_id, key_type.as_ref(), organisation, key);
        self.store_key(&key).await?;
        Ok(key)
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_attestation_proofs(
        &self,
        attestation_key: Key,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        provider_info: &WalletProviderInfo,
        nonce: Option<String>,
        os: WalletInstanceOs,
    ) -> Result<AttestationProofs, HolderWalletInstanceError> {
        let key_storage = self.key_provider.get_key_storage(key_storage_id)?;

        let attestation = key_storage
            .generate_attestation(&attestation_key, nonce.clone())
            .await
            .error_while("getting attestation")?;

        // Use SignatureProvider that uses the attestation key and the key_storage.sign_with_attestation_key method
        let auth_fn = self.key_provider.get_attestation_signature_provider(
            &attestation_key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let attestation_key_proof = self
            .create_signed_key_possession_proof(
                self.clock.now_utc(),
                &provider_info.name,
                auth_fn,
                &provider_info.url,
                nonce.clone(),
            )
            .await?;

        let (device_sig_pop, device_sig_key) = if os == WalletInstanceOs::Ios {
            let device_signing_key = self
                .new_key(key_storage_id, key_type, organisation, &key_storage)
                .await?;

            let key_handle = key_storage
                .key_handle(&device_signing_key)
                .error_while("getting key handle")?;

            let auth_fn = self.key_provider.get_signature_provider(
                &device_signing_key,
                None,
                self.key_algorithm_provider.clone(),
            )?;
            let signed_proof = self
                .create_device_signing_key_pop(
                    self.clock.now_utc(),
                    auth_fn,
                    key_handle.public_key_as_jwk().error_while("creating JWK")?,
                    &provider_info.name,
                    &provider_info.url,
                    nonce,
                )
                .await?;
            (Some(signed_proof), Some(device_signing_key))
        } else {
            (None, None)
        };

        Ok(AttestationProofs {
            attestation,
            attestation_key_proof,
            device_sig_pop,
            key: device_sig_key.unwrap_or(attestation_key),
        })
    }

    async fn resolve_os_and_key_storage(
        &self,
    ) -> Result<(WalletInstanceOs, &str), HolderWalletInstanceError> {
        let os = WalletInstanceOs::from(self.os_info_provider.get_os_name().await);
        let key_storage_type = match os {
            WalletInstanceOs::Android | WalletInstanceOs::Ios => KeyStorageType::SecureElement,
            WalletInstanceOs::Web => KeyStorageType::Internal,
        };
        let key_storage_id = self
            .config
            .key_storage
            .iter()
            .filter(|(_, v)| v.enabled && v.r#type == key_storage_type)
            .map(|(k, _)| k)
            .next()
            .ok_or(MissingProviderError::KeyStorage(format!(
                "No enabled key storage of type {key_storage_type}"
            )))
            .error_while("finding key storage")?;
        Ok((os, key_storage_id))
    }

    fn parse_and_validate_key_type(
        &self,
        key_type: &str,
    ) -> Result<KeyAlgorithmType, HolderWalletInstanceError> {
        let parsed = KeyAlgorithmType::from_str(key_type)
            .map_err(|err| HolderWalletInstanceError::InvalidKeyAlgorithm(err.to_string()))?;
        if let Some(key_algorithm) = self.config.key_algorithm.get(&parsed) {
            if !key_algorithm.enabled {
                return Err(HolderWalletInstanceError::InvalidKeyAlgorithm(
                    key_type.to_owned(),
                ));
            }
        } else {
            return Err(HolderWalletInstanceError::InvalidKeyAlgorithm(
                key_type.to_owned(),
            ));
        }
        Ok(parsed)
    }

    async fn generate_key_and_proof(
        &self,
        key_storage_id: &str,
        key_type: KeyAlgorithmType,
        organisation: Organisation,
        provider_info: &WalletProviderInfo,
        nonce: Option<String>,
    ) -> Result<(Key, String), HolderWalletInstanceError> {
        let key_storage = self.key_provider.get_key_storage(key_storage_id)?;
        let key = self
            .new_key(key_storage_id, key_type, organisation, &key_storage)
            .await?;
        let auth_fn = self.key_provider.get_signature_provider(
            &key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let proof = self
            .create_signed_key_possession_proof(
                self.clock.now_utc(),
                &provider_info.name,
                auth_fn,
                &provider_info.url,
                nonce,
            )
            .await?;
        Ok((key, proof))
    }

    async fn register(
        &self,
        url: &str,
        register_request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, HolderWalletInstanceError> {
        Ok(self
            .wallet_provider_client
            .register(url, register_request)
            .await
            .error_while("registering wallet unit")?)
    }

    async fn store_key(&self, key: &Key) -> Result<(), HolderWalletInstanceError> {
        self.key_repository
            .create_key(key.clone())
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => HolderWalletInstanceError::KeyAlreadyExists,
                err => err.error_while("creating key").into(),
            })?;
        Ok(())
    }

    async fn create_signed_key_possession_proof(
        &self,
        now: OffsetDateTime,
        wallet_provider_name: &str,
        auth_fn: AuthenticationFn,
        audience: &str,
        nonce: Option<String>,
    ) -> Result<String, HolderWalletInstanceError> {
        let proof = Jwt::new(
            "jwt".to_string(),
            auth_fn
                .jose_alg()
                .error_while("preparing key possession proof header")?,
            auth_fn.get_key_id(),
            None,
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now + Duration::minutes(60)),
                invalid_before: Some(now),
                issuer: None,
                subject: self
                    .base_url
                    .clone()
                    .map(|base_url| format!("{base_url}/{wallet_provider_name}")),
                audience: Some(vec![audience.to_owned()]),
                jwt_id: None,
                proof_of_possession_key: None,
                custom: NoncePayload { nonce },
            },
        );

        let signed_proof = proof
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating key possession proof token")?;
        Ok(signed_proof)
    }

    async fn create_device_signing_key_pop(
        &self,
        now: OffsetDateTime,
        auth_fn: AuthenticationFn,
        public_key: PublicJwk,
        wallet_provider_name: &str,
        audience: &str,
        nonce: Option<String>,
    ) -> Result<String, HolderWalletInstanceError> {
        let proof = Jwt::new(
            "jwt".to_string(),
            auth_fn
                .jose_alg()
                .error_while("preparing device signing key POP header")?,
            None,
            Some(JwtPublicKeyInfo::Jwk(public_key)),
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now + Duration::minutes(60)),
                invalid_before: Some(now),
                issuer: None,
                subject: self
                    .base_url
                    .clone()
                    .map(|base_url| format!("{base_url}/{wallet_provider_name}")),
                audience: Some(vec![audience.to_owned()]),
                jwt_id: None,
                proof_of_possession_key: None,
                custom: NoncePayload { nonce },
            },
        );

        let signed_proof = proof
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating device signing proof token")?;
        Ok(signed_proof)
    }
}

struct WalletProviderInfo {
    name: String,
    url: String,
}

enum RegistrationStatus {
    PendingNoIntegrityCheck {
        wallet_instance_id: WalletInstanceId,
        user_nonce: String,
        key: Key,
    },
    PendingIntegrityCheck {
        wallet_instance_id: WalletInstanceId,
        user_nonce: String,
        nonce: String,
    },
    Active {
        wallet_instance_id: WalletInstanceId,
        key: Key,
    },
    Unattested {
        wallet_instance_id: WalletInstanceId,
    },
}

impl RegistrationStatus {
    fn map_to_create_wallet_instance_request(
        self,
        request: &HolderRegisterWalletInstanceRequestDTO,
        organisation: &Organisation,
        wallet_provider_url: String,
        metadata: &WalletProviderMetadataResponseDTO,
    ) -> CreateHolderWalletInstanceRequest {
        match self {
            RegistrationStatus::PendingNoIntegrityCheck {
                wallet_instance_id,
                user_nonce,
                key,
            } => CreateHolderWalletInstanceRequest {
                id: Uuid::new_v4().into(),
                status: WalletInstanceStatus::Pending,
                wallet_provider_url,
                wallet_provider_type: request.wallet_provider.r#type,
                wallet_provider_name: metadata.name.clone(),
                organisation: organisation.clone(),
                authentication_key: Some(key),
                provider_wallet_unit_id: wallet_instance_id,
                trusted_rp_required: request.trusted_rp_required,
                nonce: None,
                user_nonce: Some(user_nonce),
            },
            RegistrationStatus::PendingIntegrityCheck {
                wallet_instance_id,
                user_nonce,
                nonce,
            } => CreateHolderWalletInstanceRequest {
                id: Uuid::new_v4().into(),
                status: WalletInstanceStatus::Pending,
                wallet_provider_url,
                wallet_provider_type: request.wallet_provider.r#type,
                wallet_provider_name: metadata.name.clone(),
                organisation: organisation.clone(),
                authentication_key: None,
                provider_wallet_unit_id: wallet_instance_id,
                trusted_rp_required: request.trusted_rp_required,
                nonce: Some(nonce),
                user_nonce: Some(user_nonce),
            },
            RegistrationStatus::Active {
                wallet_instance_id,
                key,
            } => CreateHolderWalletInstanceRequest {
                id: Uuid::new_v4().into(),
                status: WalletInstanceStatus::Active,
                wallet_provider_url,
                wallet_provider_type: request.wallet_provider.r#type,
                wallet_provider_name: metadata.name.clone(),
                organisation: organisation.clone(),
                authentication_key: Some(key),
                provider_wallet_unit_id: wallet_instance_id,
                trusted_rp_required: request.trusted_rp_required,
                nonce: None,
                user_nonce: None,
            },
            RegistrationStatus::Unattested { wallet_instance_id } => {
                CreateHolderWalletInstanceRequest {
                    id: Uuid::new_v4().into(),
                    status: WalletInstanceStatus::Unattested,
                    wallet_provider_url,
                    wallet_provider_type: request.wallet_provider.r#type,
                    wallet_provider_name: metadata.name.clone(),
                    organisation: organisation.clone(),
                    authentication_key: None,
                    provider_wallet_unit_id: wallet_instance_id,
                    trusted_rp_required: request.trusted_rp_required,
                    nonce: None,
                    user_nonce: None,
                }
            }
        }
    }
}

struct AttestationProofs {
    attestation: Vec<String>,
    attestation_key_proof: String,
    device_sig_pop: Option<String>,
    key: Key,
}
