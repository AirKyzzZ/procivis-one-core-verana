use std::collections::HashMap;

use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    DisplayNameDTO, EudiWalletGeneralInfo, EudiWalletInfo, EudiWalletInfoConfig,
    RegisterWalletUnitRequestDTO, WalletUnitFilterParamsDTO, WscdInfo,
};
use super::error::WalletProviderError;
use crate::config::core_config::WalletProviderType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::organisation::Organisation;
use crate::model::wallet_instance::{
    WalletInstance, WalletInstanceFilterValue, WalletInstanceStatus,
};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::repository::error::DataLayerError;
use crate::service::error::ServiceError;

pub(crate) fn wallet_unit_from_request(
    request: RegisterWalletUnitRequestDTO,
    organisation: Organisation,
    wallet_provider_type: WalletProviderType,
    public_key: Option<&PublicJwk>,
    now: OffsetDateTime,
    nonce: Option<String>,
) -> Result<WalletInstance, WalletProviderError> {
    let status = match &nonce {
        None => WalletInstanceStatus::Active,
        Some(_) => WalletInstanceStatus::Pending,
    };
    Ok(WalletInstance {
        id: Uuid::new_v4().into(),
        name: format!(
            "{}-{}-{}",
            wallet_provider_type,
            request.os,
            now.unix_timestamp()
        ),
        created_date: now,
        last_modified: now,
        last_issuance: None,
        os: request.os,
        status,
        wallet_provider_name: request.wallet_provider,
        wallet_provider_type: wallet_provider_type.into(),
        authentication_key_jwk: public_key.cloned(),
        nonce,
        organisation: Some(organisation),
        attested_keys: None,
    })
}

pub(crate) fn public_key_from_wallet_unit(
    wallet_unit: &WalletInstance,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<KeyHandle, WalletProviderError> {
    let ParsedKey { key, .. } = key_algorithm_provider
        .parse_jwk(wallet_unit.authentication_key_jwk.as_ref().ok_or(
            WalletProviderError::MappingError("Missing public key".to_string()),
        )?)
        .error_while("parsing wallet unit JWK")?;
    Ok(key)
}

pub(super) fn map_already_exists_error(error: DataLayerError) -> WalletProviderError {
    match error {
        DataLayerError::AlreadyExists => {
            WalletProviderError::WalletUnitAlreadyExists.error_while("creating wallet unit")
        }
        e => e.error_while("creating wallet unit"),
    }
    .into()
}

impl From<EudiWalletInfoConfig> for EudiWalletInfo {
    fn from(value: EudiWalletInfoConfig) -> Self {
        Self {
            general_info: EudiWalletGeneralInfo {
                wallet_provider_name: value.provider_name,
                wallet_solution_id: value.solution_id,
                wallet_solution_version: value.solution_version,
            },
            wscd_info: Some(WscdInfo {
                wscd_type: value.wscd_type,
            }),
        }
    }
}

pub(super) fn params_into_display_names(params: HashMap<String, String>) -> Vec<DisplayNameDTO> {
    params
        .into_iter()
        .map(|(lang, value)| DisplayNameDTO { lang, value })
        .collect()
}

impl TryFrom<WalletUnitFilterParamsDTO> for ListFilterCondition<WalletInstanceFilterValue> {
    type Error = ServiceError;

    fn try_from(value: WalletUnitFilterParamsDTO) -> Result<Self, Self::Error> {
        let organisation_id =
            WalletInstanceFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            WalletInstanceFilterValue::Name(StringMatch {
                r#match: StringMatchType::StartsWith,
                value: name,
            })
        });

        let ids = value.ids.map(WalletInstanceFilterValue::Ids);

        let status = value.status.map(WalletInstanceFilterValue::Status);

        let os = value.os.map(WalletInstanceFilterValue::Os);

        let attestation = value
            .attestation
            .map(|attestation| {
                let attestation_hash = SHA256.hash_base64(attestation.as_bytes()).map_err(|e| {
                    ServiceError::MappingError(format!(
                        "Could not hash wallet unit attestation: {e}"
                    ))
                })?;
                Ok::<_, ServiceError>(WalletInstanceFilterValue::AttestationHash(attestation_hash))
            })
            .transpose()?;

        let wallet_provider_type = value
            .wallet_provider_type
            .map(WalletInstanceFilterValue::WalletProviderType);

        let created_date_after = value.created_date_after.map(|date| {
            WalletInstanceFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            WalletInstanceFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(organisation_id
            & name
            & ids
            & status
            & os
            & wallet_provider_type
            & attestation
            & created_date_after
            & created_date_before)
    }
}
