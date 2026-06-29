use serde::{Deserialize, Serialize};

use crate::etsi_119_602::xml;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum OtherInformationKind {
    LoTEType(String),
    SchemeOperatorName(xml::MultiLangNameList),
    MimeType(String),
    SchemeTypeCommunityRules(xml::MultiLangUriList),
    SchemeTerritory(String),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct RawOtherInformation {
    #[serde(rename = "$value")]
    kind: OtherInformationKind,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct RawAdditionalInformation {
    #[serde(rename = "OtherInformation", default)]
    items: Vec<RawOtherInformation>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum RawDigitalIdKind {
    X509Certificate(String),
    X509SubjectName(String),
    #[serde(rename = "ds:KeyValue", alias = "KeyValue")]
    KeyValue(serde_json::Value),
    X509SKI(String),
    OtherId(String),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct RawDigitalId {
    #[serde(rename = "$value")]
    kind: RawDigitalIdKind,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
struct RawServiceDigitalIdentity {
    #[serde(rename = "DigitalId", default)]
    digital_ids: Vec<RawDigitalId>,
}

impl serde::Serialize for xml::ServiceDigitalIdentity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RawServiceDigitalIdentity::from(self).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for xml::ServiceDigitalIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from(RawServiceDigitalIdentity::deserialize(
            deserializer,
        )?))
    }
}

impl From<&xml::ServiceDigitalIdentity> for RawServiceDigitalIdentity {
    fn from(s: &xml::ServiceDigitalIdentity) -> Self {
        use RawDigitalIdKind::*;
        let mut digital_ids = Vec::new();
        let wrap = |kind| RawDigitalId { kind };

        if let Some(v) = &s.x509_certificates {
            digital_ids.extend(v.iter().cloned().map(X509Certificate).map(&wrap));
        }
        if let Some(v) = &s.x509_subject_names {
            digital_ids.extend(v.iter().cloned().map(X509SubjectName).map(&wrap));
        }
        if let Some(v) = &s.public_key_values {
            digital_ids.extend(v.iter().cloned().map(KeyValue).map(&wrap));
        }
        if let Some(v) = &s.x509_skis {
            digital_ids.extend(v.iter().cloned().map(X509SKI).map(&wrap));
        }
        if let Some(v) = &s.other_ids {
            digital_ids.extend(v.iter().cloned().map(OtherId).map(&wrap));
        }

        Self { digital_ids }
    }
}

impl From<RawServiceDigitalIdentity> for xml::ServiceDigitalIdentity {
    fn from(raw: RawServiceDigitalIdentity) -> Self {
        let mut out = Self::default();
        for RawDigitalId { kind } in raw.digital_ids {
            match kind {
                RawDigitalIdKind::X509Certificate(v) => {
                    out.x509_certificates.get_or_insert_with(Vec::new).push(v)
                }
                RawDigitalIdKind::X509SubjectName(v) => {
                    out.x509_subject_names.get_or_insert_with(Vec::new).push(v)
                }
                RawDigitalIdKind::KeyValue(v) => {
                    out.public_key_values.get_or_insert_with(Vec::new).push(v)
                }
                RawDigitalIdKind::X509SKI(v) => out.x509_skis.get_or_insert_with(Vec::new).push(v),
                RawDigitalIdKind::OtherId(v) => out.other_ids.get_or_insert_with(Vec::new).push(v),
            }
        }
        out
    }
}

impl serde::Serialize for xml::AdditionalInformation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RawAdditionalInformation::from(self.clone()).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for xml::AdditionalInformation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawAdditionalInformation::deserialize(deserializer)?;
        Ok(Self::from(raw))
    }
}
impl From<RawAdditionalInformation> for xml::AdditionalInformation {
    fn from(raw: RawAdditionalInformation) -> Self {
        let mut out = Self {
            lote_type: None,
            scheme_operator_name: None,
            mime_type: None,
            scheme_type_community_rules: None,
            scheme_territory: None,
        };
        for RawOtherInformation { kind } in raw.items {
            match kind {
                OtherInformationKind::LoTEType(v) => out.lote_type = Some(v),
                OtherInformationKind::SchemeOperatorName(v) => out.scheme_operator_name = Some(v),
                OtherInformationKind::MimeType(v) => out.mime_type = Some(v),
                OtherInformationKind::SchemeTypeCommunityRules(v) => {
                    out.scheme_type_community_rules = Some(v)
                }
                OtherInformationKind::SchemeTerritory(v) => out.scheme_territory = Some(v),
            }
        }
        out
    }
}

impl From<xml::AdditionalInformation> for RawAdditionalInformation {
    fn from(a: xml::AdditionalInformation) -> Self {
        use OtherInformationKind::*;
        let wrap = |kind| RawOtherInformation { kind };
        let mut items = Vec::new();
        if let Some(v) = a.lote_type {
            items.push(wrap(LoTEType(v)));
        }
        if let Some(v) = a.scheme_operator_name {
            items.push(wrap(SchemeOperatorName(v)));
        }
        if let Some(v) = a.mime_type {
            items.push(wrap(MimeType(v)));
        }
        if let Some(v) = a.scheme_type_community_rules {
            items.push(wrap(SchemeTypeCommunityRules(v)));
        }
        if let Some(v) = a.scheme_territory {
            items.push(wrap(SchemeTerritory(v)));
        }
        Self { items }
    }
}
