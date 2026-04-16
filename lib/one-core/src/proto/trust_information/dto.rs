use serde::{Deserialize, Serialize};
use shared_types::i18n::I18nString;
use time::OffsetDateTime;

use crate::proto::jwt::model::JWTPayload;
use crate::proto::wrp_validator::model::WRPPayload;
use crate::provider::signer::registration_certificate::model::Payload;
use crate::util::access_cert_parser::EtsiParsedAccessCert;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustInformation {
    pub received_at: OffsetDateTime,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustPurpose {
    pub purpose: I18nString,
}

pub(crate) enum TrustDetails {
    Etsi {
        wrp: WalletRelyingPartyDetails,
        access_certificate: EtsiParsedAccessCert,
    },
}

pub(crate) enum WalletRelyingPartyDetails {
    RegistrationCertificate(JWTPayload<Payload>),
    NationalRegistryInfo(JWTPayload<WRPPayload>),
}
