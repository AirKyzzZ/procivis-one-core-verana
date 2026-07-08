//! Cloud Signature Consortium (CSC) "Data model for remote signature applications" v1.0.0.
//!
//! <https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/csc-dm.pdf>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// `documentInfo` object (section 8.2), extended with the `access`, `href` and
/// `checksum` parameters of `documentReference` (section 8.3) as used by the
/// `qesApprovalRequest` examples of the data model bindings.
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentInfo {
    pub label: Option<String>,
    /// base64-encoded octet-representation of the hash of the document
    pub hash: String,
    /// `sdr`, `dtbsr` or `sodr`; `dtbsr` when absent
    #[serde(rename = "hashType")]
    pub hash_type: Option<String>,
    pub access: Option<AccessControlMethod>,
    pub href: Option<String>,
    /// W3C Subresource Integrity format, e.g. `sha256-<base64>`
    pub checksum: Option<String>,
    pub signed_props: Option<Vec<SignedAttribute>>,
    #[serde(rename = "circumstantialData")]
    pub circumstantial_data: Option<String>,
}

/// `accessControlMethod` object (section 8.3.1) for accessing the resource located by
/// `href`. Other collision-resistant type identifiers are permitted by the spec but not
/// supported here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AccessControlMethod {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "OTP")]
    Otp {
        #[serde(rename = "oneTimePassword")]
        one_time_password: String,
    },
}

/// `attribute` object (section 7.2): a signed attribute or property.
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAttribute {
    pub attribute_name: String,
    pub attribute_value: Option<String>,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn otp_access_control_method_roundtrips() {
        let example = json!({ "type": "OTP", "oneTimePassword": "51623" });

        let access: AccessControlMethod = serde_json::from_value(example.clone()).unwrap();
        assert_eq!(
            access,
            AccessControlMethod::Otp {
                one_time_password: "51623".to_string()
            }
        );
        assert_eq!(serde_json::to_value(&access).unwrap(), example);
    }
}
