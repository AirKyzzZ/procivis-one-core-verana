//! ETSI TS 119 612 — Trusted Lists (TSL / List of Trusted Lists).
//!
//! XML binding types for the `TrustServiceStatusList` format used by the EU
//! LOTL (`TSLType = EUlistofthelists`) and member-state lists
//! (`TSLType = EUgeneric`).

use serde::{Deserialize, Serialize};
use strum::Display;

pub mod xml;

/// Pointer MIME type for a TS 119 612 TSL (used to classify LOTL pointers).
pub const MIME_TSL_XML: &str = "application/vnd.etsi.tsl+xml";

/// `TSLType` (TS 119 612 clause 5.3.3, registry Annex D.5.1 / D.6).
#[derive(Clone, Debug, PartialEq, Eq, Display, Serialize)]
#[serde(into = "String")]
pub enum TslType {
    /// `EUgeneric` — a member-state list.
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric")]
    Generic,
    /// `EUlistofthelists` — the root list of lists (LOTL).
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists")]
    ListOfLists,
    /// `CClist` — a non-EU country-code member list.
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClist")]
    CcList,
    /// `CClistofthelists` — a non-EU country-code list of lists.
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClistofthelists")]
    CcListOfLists,
    /// A `TSLType` outside the registry (clause 5.3.3 / D.3 self-defined URIs,
    /// or a list defined by another spec, e.g. a TS 119 602 LoTE pointer).
    #[strum(to_string = "{0}")]
    Other(String),
}

impl From<String> for TslType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric" => Self::Generic,
            "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists" => Self::ListOfLists,
            "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClist" => Self::CcList,
            "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClistofthelists" => {
                Self::CcListOfLists
            }
            _ => Self::Other(s),
        }
    }
}

impl<'de> Deserialize<'de> for TslType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

impl From<TslType> for String {
    fn from(t: TslType) -> Self {
        t.to_string()
    }
}

/// `ServiceTypeIdentifier` (TS 119 612 clause 5.5.1). Only the EAA service types
/// relevant to attestation issuers are named; every other URI — spec-defined or
/// an extension under clause 5.5.1.0 (d) — falls into `Other`.
#[derive(Clone, Debug, PartialEq, Eq, Display, Serialize)]
#[serde(into = "String")]
pub enum ServiceType {
    /// `Svctype/EAA` — non-qualified electronic attestation of attributes.
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/Svctype/EAA")]
    Eaa,
    /// `Svctype/EAA/Q` — qualified electronic attestation of attributes.
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q")]
    EaaQ,
    /// `Svctype/EAA/Pub-EAA` — EAA issued by a public-sector body.
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA")]
    EaaPubEaa,
    /// Any other `ServiceTypeIdentifier`.
    #[strum(to_string = "{0}")]
    Other(String),
}

impl From<String> for ServiceType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "http://uri.etsi.org/TrstSvc/Svctype/EAA" => Self::Eaa,
            "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q" => Self::EaaQ,
            "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA" => Self::EaaPubEaa,
            _ => Self::Other(s),
        }
    }
}

impl<'de> Deserialize<'de> for ServiceType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

impl From<ServiceType> for String {
    fn from(t: ServiceType) -> Self {
        t.to_string()
    }
}

/// `ServiceStatus` (TS 119 612 clause 5.5.4, registry Annex D.5.6).
#[derive(Clone, Debug, PartialEq, Eq, Display, Serialize)]
#[serde(into = "String")]
pub enum ServiceStatus {
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision")]
    UnderSupervision,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation")]
    SupervisionInCessation,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased")]
    SupervisionCeased,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked")]
    SupervisionRevoked,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited")]
    Accredited,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased")]
    AccreditationCeased,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked")]
    AccreditationRevoked,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")]
    Granted,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn")]
    Withdrawn,
    #[strum(to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw")]
    SetByNationalLaw,
    #[strum(
        to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"
    )]
    RecognisedAtNationalLevel,
    #[strum(
        to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw"
    )]
    DeprecatedByNationalLaw,
    #[strum(
        to_string = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel"
    )]
    DeprecatedAtNationalLevel,
    #[strum(to_string = "{0}")]
    Other(String),
}

impl From<String> for ServiceStatus {
    fn from(s: String) -> Self {
        match s.as_str() {
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision" => {
                Self::UnderSupervision
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation" => {
                Self::SupervisionInCessation
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased" => {
                Self::SupervisionCeased
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked" => {
                Self::SupervisionRevoked
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited" => Self::Accredited,
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased" => {
                Self::AccreditationCeased
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked" => {
                Self::AccreditationRevoked
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted" => Self::Granted,
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn" => Self::Withdrawn,
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw" => {
                Self::SetByNationalLaw
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel" => {
                Self::RecognisedAtNationalLevel
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw" => {
                Self::DeprecatedByNationalLaw
            }
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel" => {
                Self::DeprecatedAtNationalLevel
            }
            _ => Self::Other(s),
        }
    }
}

impl<'de> Deserialize<'de> for ServiceStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

impl From<ServiceStatus> for String {
    fn from(s: ServiceStatus) -> Self {
        s.to_string()
    }
}
