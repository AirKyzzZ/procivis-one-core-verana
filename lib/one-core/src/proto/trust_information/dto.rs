use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::proto::jwt::model::JWTPayload;
use crate::proto::wrp_validator::model::WRPPayload;
use crate::provider::signer::registration_certificate::model::Payload;
use crate::util::access_cert_parser::EtsiParsedAccessCert;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustInformationDTO {
    pub received_at: OffsetDateTime,
    pub name: String,
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
