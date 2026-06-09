use std::collections::HashMap;

use one_dto_mapper::From;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::{RevocationMethodId, TrustCollectionId, WalletInstanceId};
use standardized_types::jwk::PublicJwk;
use time::{Duration, OffsetDateTime};

use crate::model::common::GetListResponse;
use crate::model::wallet_instance::{
    WalletInstance, WalletInstanceOs, WalletInstanceStatus, WalletProviderType,
};
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;

#[derive(Clone, Debug)]
pub struct RegisterWalletUnitRequestDTO {
    pub wallet_provider: String,
    pub os: WalletInstanceOs,
    pub public_key: Option<PublicJwk>,
    pub proof: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RegisterWalletUnitResponseDTO {
    pub id: WalletInstanceId,
    pub nonce: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ActivateWalletUnitRequestDTO {
    pub attestation: Vec<String>,
    pub attestation_key_proof: String,
    pub device_signing_key_proof: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WalletUnitActivationRequestDTO {
    pub attestation: Vec<String>,
    pub attestation_key_proof: String,
    pub device_signing_key_proof: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RefreshWalletUnitRequestDTO {
    pub proof: String,
}

#[derive(Clone, Debug)]
pub struct IssueWalletUnitAttestationRequestDTO {
    pub wia: Vec<IssueWiaRequestDTO>,
    pub wua: Vec<IssueWuaRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct IssueWiaRequestDTO {
    pub proof: String,
}

#[derive(Clone, Debug)]
pub struct IssueWuaRequestDTO {
    pub proof: String,
    pub security_level: KeyStorageSecurityLevel,
}

#[derive(Clone, Debug)]
pub struct IssueWalletUnitAttestationResponseDTO {
    pub wia: Vec<String>,
    pub wua: Vec<String>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletProviderParams {
    pub wallet_name: String,
    pub wallet_link: String,
    pub wallet_client_id: String,
    // Information for wallet whether it enforces having a wallet unit attestation when starting app
    pub wallet_registration: WalletRegistrationRequirement,
    pub wallet_instance_attestation: WalletInstanceAttestationParams,
    pub wallet_unit_attestation: WalletUnitAttestationParams,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub device_auth_leeway: Duration,
    pub app_version: Option<AppVersionDTO>,
    pub eudi_wallet_info: Option<EudiWalletInfoConfig>,
    #[serde(default)]
    pub trust_collections: HashMap<TrustCollectionId, TrustCollectionParams>, // FIX ME: This is a temporary solution, should be changed to a proper structure ONE-9309
    pub feature_flags: FeatureFlags,
    pub user_authentication: Option<UserAuthenticationParams>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureFlags {
    pub trust_ecosystems_enabled: bool,
    pub refresh_credential_batch_enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserAuthenticationParams {
    pub required: bool,
    pub identity_provider: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub token_validation: TokenValidationParams,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenValidationParams {
    pub aud: String,
    pub iss: String,
    pub jwks_uri: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TrustCollectionParams {
    pub logo: String,
    pub display_name: HashMap<String, String>,
    pub description: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum WalletRegistrationRequirement {
    Mandatory,
    Optional,
    Disabled,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletInstanceAttestationParams {
    pub expiration_time: u64,
    #[serde(default)]
    pub integrity_check: IntegrityCheck,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WalletUnitAttestationParams {
    pub expiration_time: u64,
    pub revocation_method: Option<RevocationMethodId>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EudiWalletInfoConfig {
    pub provider_name: String,
    pub solution_id: String,
    pub solution_version: String,
    pub wscd_type: WscdType,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WscdType {
    Remote,
    LocalExternal,
    LocalInternal,
    LocalNative,
    Hybrid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppVersionDTO {
    pub minimum: String,
    pub minimum_recommended: Option<String>,
    #[serde(default)]
    pub reject: Vec<String>,
    pub update_screen: Option<UpdateScreenDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateScreenDTO {
    pub link: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AndroidBundle {
    pub bundle_id: String,
    #[serde(
        rename = "signingCertificateFingerprints",
        deserialize_with = "deserialize_signing_certificate_fingerprints"
    )]
    pub signing_certificate_fingerprints: Vec<String>,
    #[serde(rename = "trustedAttestationCAs")]
    pub trusted_attestation_cas: Vec<String>,
}

fn deserialize_signing_certificate_fingerprints<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Vec<String> = Deserialize::deserialize(d)?;
    Ok(s.iter()
        .map(|s| s.replace(":", "").to_uppercase())
        .collect())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IntegrityCheck {
    pub android: Option<AndroidBundle>,
    pub ios: Option<IOSBundle>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_attestation_timeout")]
    pub timeout: usize,
}

impl Default for IntegrityCheck {
    fn default() -> Self {
        Self {
            android: None,
            ios: None,
            enabled: true,
            timeout: 300,
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_attestation_timeout() -> usize {
    300
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IOSBundle {
    pub bundle_id: String,
    #[serde(rename = "trustedAttestationCAs")]
    pub trusted_attestation_cas: Vec<String>,
    pub enforce_production_build: bool,
}

#[derive(Debug, From)]
#[from(WalletInstance)]
pub struct GetWalletUnitResponseDTO {
    pub id: WalletInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: WalletInstanceOs,
    pub status: WalletInstanceStatus,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub authentication_key_jwk: Option<PublicJwk>,
}

pub type GetWalletUnitListResponseDTO = GetListResponse<GetWalletUnitResponseDTO>;

#[derive(Clone, Debug)]
pub struct WalletUnitFilterParamsDTO {
    pub name: Option<String>,
    pub ids: Option<Vec<shared_types::WalletInstanceId>>,
    pub status: Option<Vec<WalletInstanceStatus>>,
    pub os: Option<Vec<WalletInstanceOs>>,
    pub wallet_provider_type: Option<Vec<String>>,
    pub attestation: Option<String>,
    pub organisation_id: shared_types::OrganisationId,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct WalletProviderMetadataResponseDTO {
    pub wallet_unit_attestation: WalletUnitAttestationMetadataDTO,
    pub name: String,
    pub app_version: Option<AppVersionDTO>,
    pub trust_collections: Vec<ProviderTrustCollectionDTO>,
    pub feature_flags: FeatureFlags,
    pub user_authentication: Option<UserAuthenticationDTO>,
}

#[derive(Clone, Debug)]
pub struct UserAuthenticationDTO {
    pub required: bool,
    pub identity_provider: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub token_validation: Option<TokenValidationDTO>,
}

#[derive(Clone, Debug)]
pub struct TokenValidationDTO {
    pub aud: String,
    pub iss: String,
    pub jwks_uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderTrustCollectionDTO {
    pub id: TrustCollectionId,
    pub name: String,
    pub logo: String,
    pub display_name: Vec<DisplayNameDTO>,
    pub description: Vec<DisplayNameDTO>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayNameDTO {
    pub lang: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct WalletUnitAttestationMetadataDTO {
    pub app_integrity_check_required: bool,
    pub enabled: bool,
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct NoncePayload {
    pub nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct WalletInstanceAttestationClaims {
    pub wallet_name: Option<String>,
    pub wallet_link: Option<String>,
    pub eudi_wallet_info: Option<EudiWalletInfo>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct WalletUnitAttestationClaims {
    pub key_storage: Vec<KeyStorageSecurityLevel>,
    pub attested_keys: Vec<PublicJwk>,
    pub eudi_wallet_info: Option<EudiWalletInfo>,
    pub status: Option<SdJwtVcStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct EudiWalletInfo {
    pub general_info: EudiWalletGeneralInfo,
    pub wscd_info: Option<WscdInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct EudiWalletGeneralInfo {
    pub wallet_provider_name: String,
    pub wallet_solution_id: String,
    pub wallet_solution_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct WscdInfo {
    pub wscd_type: WscdType,
}
