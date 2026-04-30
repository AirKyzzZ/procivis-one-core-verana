use one_dto_mapper::Into;
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use url::Url;

use crate::proto::jwt::model::JWTPayload;
use crate::provider::signer::registration_certificate;
use crate::provider::signer::registration_certificate::model::Policy;
use crate::provider::trust_list_subscriber::TrustEntityResponse;

pub(crate) struct AccessCertificateResult {
    #[expect(unused)]
    pub trust_entity: Option<TrustEntityResponse>,
    pub relying_party_id: String,
    pub registry_url: Option<Url>,
}

pub(crate) struct RegistrationCertificateResult {
    #[expect(unused)]
    pub trust_entity: Option<TrustEntityResponse>,
    pub payload: JWTPayload<registration_certificate::model::Payload>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum TrustMode {
    /// Only interactions with trusted parties allowed, untrusted operations result in failure
    TrustMandatory,

    /// Both trusted and untrusted operations allowed,
    /// trusted operations will result in additional history events describing validated trust information
    TrustOptional,

    /// No trust checking performed, operations will result in `Unknown` trust results
    Disabled,
}

impl TrustMode {
    pub fn optional() -> Self {
        Self::TrustOptional
    }
}

pub(crate) struct FetchRegistryResult {
    #[expect(unused)]
    pub trust_entity: Option<TrustEntityResponse>,
    pub payload: JWTPayload<WRPPayload>,
    pub jwt: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct RegistryKeys {
    pub keys: Vec<PublicJwk>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WRPPayload {
    pub data: WRPPayloadData,
}

/// temporary JWT payload, until it is clearly defined
/// matches <https://gitlab.procivis.ch/procivis/one/one-java-commons/-/blob/main/one-public-api/src/main/java/com/procivis/pub/api/wrpr/dto/PublicWalletRelyingPartyDTO.java>
#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WRPPayloadData {
    pub trade_name: Option<String>,
    #[serde(rename = "supportURI")]
    pub support_uri: Vec<Url>,
    pub srv_description: Vec<MultiLangString>,
    #[serde(default)]
    pub intended_use: Vec<IntendedUse>,
    #[serde(default, rename = "isPSB")]
    pub is_psb: Option<bool>,
    #[expect(unused)]
    pub entitlement: Vec<String>,
    #[serde(default)]
    pub provides_attestations: Vec<Credential>,
    pub supervisory_authority: LegalEntity,
    #[serde(rename = "registryURI")]
    #[expect(unused)]
    pub registry_uri: Url,
    pub uses_intermediary: Option<Vec<WalletRelyingParty>>,
    #[expect(unused)]
    pub legal_person: Option<LegalPerson>,
    #[expect(unused)]
    pub natural_person: Option<NaturalPerson>,
    #[serde(default)]
    #[expect(unused)]
    pub identifier: Vec<Identifier>,
    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    #[expect(unused)]
    pub postal_address: Option<Vec<String>>,
    pub country: String,
    #[serde(default)]
    pub email: Vec<String>,
    #[serde(default)]
    pub phone: Vec<String>,
    #[serde(default, rename = "infoURI")]
    #[expect(unused)]
    pub info_uri: Vec<Url>,
}

/// B.2.1 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[expect(unused)]
pub(crate) struct WalletRelyingParty {
    pub trade_name: Option<String>,
    #[serde(rename = "supportURI")]
    pub support_uri: Vec<Url>,
    pub srv_description: Vec<MultiLangString>,
    #[serde(default)]
    pub intended_use: Vec<IntendedUse>,
    #[serde(rename = "isPSB")]
    pub is_psb: bool,
    pub entitlement: Vec<String>,
    #[serde(default)]
    pub provides_attestations: Vec<Credential>,
    pub supervisory_authority: LegalEntity,
    #[serde(rename = "registryURI")]
    pub registry_uri: Url,
    pub uses_intermediary: Option<Vec<WalletRelyingParty>>,
}

/// B.2.2 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[expect(unused)]
pub(crate) struct LegalEntity {
    pub legal_person: Option<LegalPerson>,
    pub natural_person: Option<NaturalPerson>,
    #[serde(default)]
    pub identifier: Vec<Identifier>,
    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub postal_address: Option<Vec<String>>,
    pub country: String,
    #[serde(default)]
    pub email: Vec<String>,
    #[serde(default)]
    pub phone: Vec<String>,
    #[serde(default, rename = "infoURI")]
    pub info_uri: Vec<String>,
}

/// B.2.3 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[expect(unused)]
pub(crate) struct LegalPerson {
    pub legal_name: Vec<String>,
    #[serde(default)]
    pub established_by_law: Vec<Law>,
}

/// B.2.4 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[expect(unused)]
pub(crate) struct NaturalPerson {
    pub given_name: String,
    pub family_name: String,
    pub date_of_birth: Option<String>,
    pub place_of_birth: Option<String>,
}

/// B.2.5 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[expect(unused)]
pub(crate) struct Identifier {
    pub r#type: String,
    pub identifier: String,
}

/// B.2.6 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Clone, Deserialize, Into)]
#[into(standardized_types::etsi_119_602::json::MultiLangString)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MultiLangString {
    pub lang: String,
    #[into(rename = "value")]
    pub content: String,
}

/// B.2.7 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[expect(unused)]
pub(crate) struct IntendedUse {
    pub purpose: Vec<MultiLangString>,
    pub privacy_policy: Vec<Policy>,

    // timestamp parsing workaround, in ETSI standard these should be ISO 8601-1 encoded
    #[serde(deserialize_with = "crate::mapper::timestamp::deserialize")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "crate::mapper::timestamp::option")]
    pub revoked_at: Option<OffsetDateTime>,
    pub credential: Vec<Credential>,
    pub intended_use_identifier: String,
}

/// B.2.9 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Credential {
    pub format: dcql::CredentialFormat,
    pub meta: dcql::CredentialMeta,
    pub claim: Option<Vec<Claim>>,
}

/// B.2.10 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Claim {
    pub path: String,
    #[serde(default)]
    pub values: Vec<dcql::ClaimValue>,
}

/// B.2.11 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[expect(unused)]
pub(crate) struct Law {
    // workaround, should be mandatory
    pub lang: Option<String>,
    pub legal_basis: String,
}
