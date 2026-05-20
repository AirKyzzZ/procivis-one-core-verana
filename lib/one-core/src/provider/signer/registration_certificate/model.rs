use std::collections::HashMap;

use dcql::CredentialFormat;
use one_dto_mapper::Into;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::proto::jwt::Jwt;
// Payload specification according to spec from:
// https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf

pub type WRPRegistrationCertificate = Jwt<Payload>;
pub type WRPRegistrationCertificatePayload = crate::proto::jwt::model::JWTPayload<Payload>;

// 5.2.4 Payload Attributes
#[derive(Debug)]
pub struct RequestData {
    pub name: String,
    pub subject: Subject,
    pub country: String,
    pub registry_uri: Url,
    pub service_description: Vec<MultiLangString>,
    pub entitlements: Vec<Entitlement>,
    pub privacy_policy: Url,
    pub info_uri: Url,
    pub supervisory_authority: SupervisoryAuthority,
    pub policy_id: Vec<String>,
    pub certificate_policy: Url,
    pub provided_attestations: Option<Vec<Credential>>,
    pub credentials: Option<Vec<Credential>>,
    pub purpose: Option<Vec<MultiLangString>>,
    pub intended_use_id: Option<String>,
    pub public_body: Option<bool>,
    pub support_uri: Url,
    pub intermediary: Option<Intermediary>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub name: String,
    pub sub_ln: Option<String>,
    pub sub_gn: Option<String>,
    pub sub_fn: Option<String>,
    pub country: String,
    pub registry_uri: Url,
    #[serde(rename = "srv_description")]
    pub service_descriptions: Vec<Vec<MultiLangString>>,
    pub entitlements: Vec<Entitlement>,
    pub privacy_policy: Url,
    pub info_uri: Url,
    pub supervisory_authority: SupervisoryAuthority,
    pub policy_id: Vec<String>,
    pub certificate_policy: Url,
    pub status: Status,
    pub provides_attestations: Option<Vec<Credential>>,
    pub credentials: Option<Vec<Credential>>,
    pub purpose: Option<Vec<MultiLangString>>,
    pub intended_use_id: Option<String>,
    pub public_body: Option<bool>,
    pub support_uri: Url,
    pub intermediary: Option<Intermediary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum Subject {
    LegalPerson {
        id: String,
        legal_name: String,
    },
    NaturalPerson {
        id: String,
        given_name: String,
        family_name: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub r#type: PolicyType,
    #[serde(rename = "policyURI")]
    pub policy_uri: Url,
}

// Values defined here: https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts2-notification-publication-provider-information.md#286-policy
// The WRPRCs are only concerned with PrivacyPolicies, but we support other policies for compatibility.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyType {
    #[serde(rename = "http://data.europa.eu/eudi/policy/trust-service-practice-statement")]
    TrustServicePracticeStatement,
    #[serde(rename = "http://data.europa.eu/eudi/policy/terms-and-conditions")]
    TermsAndConditions,
    #[serde(rename = "http://data.europa.eu/eudi/policy/privacy-statement")]
    PrivacyStatement,
    #[serde(rename = "http://data.europa.eu/eudi/policy/privacy-policy")]
    PrivacyPolicy,
    #[serde(rename = "http://data.europa.eu/eudi/policy/registration-policy")]
    RegistrationPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize, Into)]
#[into(standardized_types::etsi_119_602::json::MultiLangString)]
#[serde(deny_unknown_fields)]
pub struct MultiLangString {
    pub lang: String,
    pub value: String,
}

// 4.2 Wallet-Relying party roles
// [...]
// The entitlements may be expressed as OIDs or structured URIs
// in certificate profiles and registration data formats.
#[derive(Debug)]
pub struct Entitlement {
    pub format: EntitlementFormat,
    pub role: EntitlementRole,
}

#[derive(Debug)]
pub enum EntitlementFormat {
    Oid,
    Uri,
}

#[derive(Debug, Eq, PartialEq)]
pub enum EntitlementRole {
    ServiceProvider,
    QeaaProvider,
    NonQeaaProvider,
    PubEaaProvider,
    PidProvider,
    QCertForESealProvider,
    QCertForESigProvider,
    RQSealCDsProvider,
    RQSigCDsProvider,
    ESigESealCreationProvider,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisoryAuthority {
    pub email: String,
    pub phone: String,
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub status_list: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub format: CredentialFormat,
    pub meta: dcql::CredentialMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim: Option<Vec<Claim>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub path: dcql::ClaimPath,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<dcql::ClaimValue>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intermediary {
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
}

impl<'de> Deserialize<'de> for RequestData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct RequestDataProto {
            pub name: String,
            #[serde(rename = "sub")]
            pub subject: Subject,
            pub country: String,
            pub registry_uri: Url,
            #[serde(rename = "service")]
            pub service_description: Vec<MultiLangString>,
            pub entitlements: Vec<Entitlement>,
            pub privacy_policy: Vec<Policy>,
            pub info_uri: Url,
            #[serde(rename = "dpa")]
            pub data_protection_authority: SupervisoryAuthority,
            pub policy_id: Vec<String>,
            pub certificate_policy: Url,
            pub provided_attestations: Option<Vec<Credential>>,
            pub credentials: Option<Vec<Credential>>,
            pub purpose: Option<Vec<MultiLangString>>,
            pub intended_use_id: Option<String>,
            pub public_body: Option<bool>,
            pub support_uri: Url,
            #[serde(rename = "act")]
            pub intermediary: Option<Intermediary>,
        }

        let proto = RequestDataProto::deserialize(deserializer)?;

        // GEN-5.2.4-03: The `entitlements` field specified in GEN-5.2.4-01 shall include
        // at least one entitlement specified in clause A.2.
        if proto.entitlements.is_empty() {
            return Err(Error::custom("Must provide at least one valid entitlement"));
        }

        // GEN-5.2.4-06: If the WRPRC is issued to the service provider
        // as specified in clause 4.2 the payload of the WRPRC shall include
        // all the fields provided by the registry specified in Table 9.
        let is_service_provider = proto
            .entitlements
            .iter()
            .any(|e| e.role == EntitlementRole::ServiceProvider);
        if is_service_provider {
            if proto.credentials.is_none() {
                return Err(Error::missing_field("credentials"));
            }
            if proto.purpose.is_none() {
                return Err(Error::missing_field("purpose"));
            }
            if proto.intended_use_id.is_none() {
                return Err(Error::missing_field("intended_use_id"));
            }
        }

        let privacy_policy = proto
            .privacy_policy
            .into_iter()
            .find(|policy| policy.r#type == PolicyType::PrivacyPolicy)
            .ok_or(Error::custom(
                "Must provide at least one policy of PrivacyPolicy type",
            ))?;

        Ok(Self {
            name: proto.name,
            subject: proto.subject,
            country: proto.country,
            registry_uri: proto.registry_uri,
            service_description: proto.service_description,
            entitlements: proto.entitlements,
            privacy_policy: privacy_policy.policy_uri,
            info_uri: proto.info_uri,
            supervisory_authority: proto.data_protection_authority,
            policy_id: proto.policy_id,
            certificate_policy: proto.certificate_policy,
            provided_attestations: proto.provided_attestations,
            credentials: proto.credentials,
            purpose: proto.purpose,
            intended_use_id: proto.intended_use_id,
            public_body: proto.public_body,
            support_uri: proto.support_uri,
            intermediary: proto.intermediary,
        })
    }
}

impl RequestData {
    pub fn get_subject_id(&self) -> &str {
        match &self.subject {
            Subject::LegalPerson { id, .. } => id.as_str(),
            Subject::NaturalPerson { id, .. } => id.as_str(),
        }
    }
}

impl EntitlementRole {
    fn get_oid(&self) -> &'static str {
        match self {
            EntitlementRole::ServiceProvider => "id-etsi-wrpa-entitlement 1",
            EntitlementRole::QeaaProvider => "id-etsi-wrpa-entitlement 2",
            EntitlementRole::NonQeaaProvider => "id-etsi-wrpa-entitlement 3",
            EntitlementRole::PubEaaProvider => "id-etsi-wrpa-entitlement 4",
            EntitlementRole::PidProvider => "id-etsi-wrpa-entitlement 5",
            EntitlementRole::QCertForESealProvider => "id-etsi-wrpa-entitlement 6",
            EntitlementRole::QCertForESigProvider => "id-etsi-wrpa-entitlement 7",
            EntitlementRole::RQSealCDsProvider => "id-etsi-wrpa-entitlement 8",
            EntitlementRole::RQSigCDsProvider => "id-etsi-wrpa-entitlement 9",
            EntitlementRole::ESigESealCreationProvider => "id-etsi-wrpa-entitlement 10",
        }
    }

    fn get_uri(&self) -> &'static str {
        match self {
            EntitlementRole::ServiceProvider => {
                "https://uri.etsi.org/19475/Entitlement/Service_Provider"
            }
            EntitlementRole::QeaaProvider => "https://uri.etsi.org/19475/Entitlement/QEAA_Provider",
            EntitlementRole::NonQeaaProvider => {
                "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
            }
            EntitlementRole::PubEaaProvider => {
                "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"
            }
            EntitlementRole::PidProvider => "https://uri.etsi.org/19475/Entitlement/PID_Provider",
            EntitlementRole::QCertForESealProvider => {
                "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider"
            }
            EntitlementRole::QCertForESigProvider => {
                "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider"
            }
            EntitlementRole::RQSealCDsProvider => {
                "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider"
            }
            EntitlementRole::RQSigCDsProvider => {
                "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider"
            }
            EntitlementRole::ESigESealCreationProvider => {
                "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider"
            }
        }
    }
}

impl Serialize for Entitlement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = match self.format {
            EntitlementFormat::Oid => self.role.get_oid(),
            EntitlementFormat::Uri => self.role.get_uri(),
        };
        serializer.serialize_str(str)
    }
}

impl<'de> Deserialize<'de> for Entitlement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let result = {
            if let Some(oid_number) = str.strip_prefix("id-etsi-wrpa-entitlement ") {
                let role = match oid_number {
                    "1" => Some(EntitlementRole::ServiceProvider),
                    "2" => Some(EntitlementRole::QeaaProvider),
                    "3" => Some(EntitlementRole::NonQeaaProvider),
                    "4" => Some(EntitlementRole::PubEaaProvider),
                    "5" => Some(EntitlementRole::PidProvider),
                    "6" => Some(EntitlementRole::QCertForESealProvider),
                    "7" => Some(EntitlementRole::QCertForESigProvider),
                    "8" => Some(EntitlementRole::RQSealCDsProvider),
                    "9" => Some(EntitlementRole::RQSigCDsProvider),
                    "10" => Some(EntitlementRole::ESigESealCreationProvider),
                    _ => None,
                };
                role.map(|role| Self {
                    format: EntitlementFormat::Oid,
                    role,
                })
            } else if let Some(url_path) =
                str.strip_prefix("https://uri.etsi.org/19475/Entitlement/")
            {
                let role = match url_path {
                    "Service_Provider" => Some(EntitlementRole::ServiceProvider),
                    "QEAA_Provider" => Some(EntitlementRole::QeaaProvider),
                    "Non_Q_EAA_Provider" => Some(EntitlementRole::NonQeaaProvider),
                    "PUB_EAA_Provider" => Some(EntitlementRole::PubEaaProvider),
                    "PID_Provider" => Some(EntitlementRole::PidProvider),
                    "QCert_for_ESeal_Provider" => Some(EntitlementRole::QCertForESealProvider),
                    "QCert_for_ESig_Provider" => Some(EntitlementRole::QCertForESigProvider),
                    "rQSealCDs_Provider" => Some(EntitlementRole::RQSealCDsProvider),
                    "rQSigCDs_Provider" => Some(EntitlementRole::RQSigCDsProvider),
                    "ESig_ESeal_Creation_Provider" => {
                        Some(EntitlementRole::ESigESealCreationProvider)
                    }
                    _ => None,
                };
                role.map(|role| Self {
                    format: EntitlementFormat::Uri,
                    role,
                })
            } else {
                None
            }
        };

        // TODO: Return a list of expected variants
        result.ok_or(D::Error::unknown_variant(str.as_str(), &[]))
    }
}

impl Payload {
    pub fn from_request_data_and_status(req: RequestData, status: Status) -> Self {
        let (sub_ln, sub_gn, sub_fn) = match req.subject {
            Subject::LegalPerson { legal_name, .. } => (Some(legal_name), None, None),
            Subject::NaturalPerson {
                given_name,
                family_name,
                ..
            } => (None, Some(given_name), Some(family_name)),
        };

        Self {
            name: req.name,
            sub_ln,
            sub_gn,
            sub_fn,
            country: req.country,
            registry_uri: req.registry_uri,
            service_descriptions: vec![req.service_description],
            entitlements: req.entitlements,
            privacy_policy: req.privacy_policy,
            info_uri: req.info_uri,
            supervisory_authority: req.supervisory_authority,
            policy_id: req.policy_id,
            certificate_policy: req.certificate_policy,
            provides_attestations: req.provided_attestations,
            credentials: req.credentials,
            purpose: req.purpose,
            intended_use_id: req.intended_use_id,
            public_body: req.public_body,
            support_uri: req.support_uri,
            intermediary: req.intermediary,
            status,
        }
    }
}
