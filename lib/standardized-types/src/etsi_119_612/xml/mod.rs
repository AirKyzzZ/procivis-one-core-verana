use serde::{Deserialize, Serialize};

use super::{ServiceStatus, ServiceType, TslType};

/// XML namespace URI for TS 119 612 `TrustServiceStatusList` elements.
/// Reserved for namespace-aware operations in later phases.
#[allow(dead_code)]
pub(crate) const TSL_NS: &str = "http://uri.etsi.org/02231/v2#";

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename = "TrustServiceStatusList", rename_all = "PascalCase")]
pub struct TrustServiceStatusList {
    pub scheme_information: SchemeInformation,
    /// Present on EUgeneric lists; absent on the LOTL.
    pub trust_service_provider_list: Option<TrustServiceProviderList>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SchemeInformation {
    #[serde(rename = "TSLVersionIdentifier")]
    pub tsl_version_identifier: u64,
    #[serde(rename = "TSLSequenceNumber")]
    pub tsl_sequence_number: u64,
    #[serde(rename = "TSLType")]
    pub tsl_type: TslType,
    #[serde(rename = "SchemeOperatorName")]
    pub scheme_operator_name: InternationalNames,
    #[serde(rename = "SchemeTerritory")]
    pub scheme_territory: Option<String>,
    #[serde(rename = "PointersToOtherTSL")]
    pub pointers_to_other_tsl: Option<PointersToOtherTsl>,
    #[serde(rename = "ListIssueDateTime", with = "crate::mapper::xml_datetime")]
    pub list_issue_date_time: time::OffsetDateTime,
    #[serde(rename = "NextUpdate")]
    pub next_update: NextUpdate,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NextUpdate {
    #[serde(
        rename = "dateTime",
        default,
        with = "crate::mapper::xml_datetime::option"
    )]
    pub date_time: Option<time::OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct InternationalNames {
    #[serde(rename = "Name", default)]
    pub names: Vec<LangString>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct LangString {
    #[serde(rename = "@xml:lang")]
    pub lang: String,
    #[serde(rename = "$text")]
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PointersToOtherTsl {
    #[serde(rename = "OtherTSLPointer", default)]
    pub pointers: Vec<OtherTslPointer>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct OtherTslPointer {
    pub service_digital_identities: ServiceDigitalIdentities,
    #[serde(rename = "TSLLocation")]
    pub tsl_location: String,
    pub additional_information: Option<AdditionalInformation>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceDigitalIdentities {
    #[serde(rename = "ServiceDigitalIdentity", default)]
    pub identities: Vec<ServiceDigitalIdentity>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceDigitalIdentity {
    #[serde(rename = "DigitalId", default)]
    pub digital_ids: Vec<DigitalId>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct DigitalId {
    /// base64 DER X.509 certificate.
    #[serde(rename = "X509Certificate")]
    pub x509_certificate: Option<String>,
    /// base64 X.509 SubjectKeyIdentifier.
    #[serde(rename = "X509SKI")]
    pub x509_ski: Option<String>,
    #[serde(rename = "X509SubjectName")]
    pub x509_subject_name: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct AdditionalInformation {
    #[serde(rename = "OtherInformation", default)]
    pub other_information: Vec<OtherInformation>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct OtherInformation {
    #[serde(rename = "TSLType")]
    pub tsl_type: Option<TslType>,
    pub scheme_territory: Option<String>,
    #[serde(rename = "MimeType")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TrustServiceProviderList {
    #[serde(rename = "TrustServiceProvider", default)]
    pub providers: Vec<TrustServiceProvider>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TrustServiceProvider {
    #[serde(rename = "TSPServices")]
    pub tsp_services: TspServices,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TspServices {
    #[serde(rename = "TSPService", default)]
    pub services: Vec<TspService>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TspService {
    pub service_information: ServiceInformation,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceInformation {
    pub service_type_identifier: ServiceType,
    pub service_name: InternationalNames,
    pub service_digital_identity: ServiceDigitalIdentity,
    pub service_status: ServiceStatus,
    #[serde(default, with = "crate::mapper::xml_datetime::option")]
    pub status_starting_time: Option<time::OffsetDateTime>,
}

#[cfg(test)]
mod test;
