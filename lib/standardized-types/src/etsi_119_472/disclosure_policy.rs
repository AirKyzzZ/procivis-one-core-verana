//! https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct DisclosurePolicy {
    pub id: String,
    #[serde(flatten)]
    pub policy: PolicyType,
    pub description: Option<String>,
    pub url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", tag = "policy")]
pub enum PolicyType {
    None,
    AllowList { options: AllowListOptions },
    RootOfTrust { options: RootOfTrustOptions },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AllowListOptions {
    /// A list of entries defining the permitted relying parties.
    /// Each entry is either a `dn` (the relying party's X.509
    /// Distinguished Name in RFC 2253 format) or an `entitlement`
    /// (an ETSI URI identifying a category of service providers).
    pub values: Vec<AllowListOption>,
}

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AllowListOption {
    pub dn: Option<String>,
    pub entitlement: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct RootOfTrustOptions {
    /// A list of entries defining the permitted relying parties.
    /// Each entry must include both the `dn` and `serial` of the
    /// CA. Use the subject DN as it appears in the CA's own certificate.
    pub values: Vec<RootOfTrustOption>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct RootOfTrustOption {
    pub dn: String,
    pub serial: String,
}
