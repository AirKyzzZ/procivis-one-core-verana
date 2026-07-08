//! Cloud Signature Consortium (CSC) "Data model bindings to protocols" v1.0.0 —
//! transaction data types for the OID4VC binding.
//!
//! <https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/data-model-bindings.pdf>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::data_model::DocumentInfo;
use super::{HashAlgorithm, SignatureQualifier};

/// Transaction data type identifier of [`QesApprovalRequest`] (section 7.1).
pub const QES_APPROVAL_TRANSACTION_DATA_TYPE: &str =
    "https://cloudsignatureconsortium.org/2025/qes-approval";

/// Key Binding JWT claim carrying the `qesApproval` value in the SD-JWT VC encoding
/// (section 7.2.1.2)
pub const QES_APPROVAL_KB_JWT_CLAIM: &str = "org.cloudsignatureconsortium.dm.1.qesApproval";

/// mdoc namespace and data element carrying the `qesApproval` value in the ISO/IEC
/// 18013-5 encoding (section 7.2.1.1)
pub const QES_APPROVAL_MDOC_NAMESPACE: &str = "org.cloudsignatureconsortium.dm.1";
pub const QES_APPROVAL_MDOC_ELEMENT: &str = "qesApproval";

/// `qesApprovalRequest` object (section 7.1.1): OpenID4VP transaction data expressing
/// the user's approval for QES creation. Union of `signatureCreationApproval` (data
/// model section 10.1) and the OpenID4VP binding parameters.
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QesApprovalRequest {
    /// MUST be [`QES_APPROVAL_TRANSACTION_DATA_TYPE`].
    pub r#type: String,
    pub credential_ids: Vec<String>,
    /// Locations of remote signing service providers as defined in RFC 9396
    pub locations: Option<Vec<String>>,
    // signatureCreationApproval (data model section 10.1); at least one of
    // `credentialID` and `signatureQualifier` must be present
    #[serde(rename = "credentialID")]
    pub credential_id: Option<String>,
    #[serde(rename = "signatureQualifier")]
    pub signature_qualifier: Option<SignatureQualifier>,
    #[serde(rename = "numSignatures")]
    pub num_signatures: u32,
    /// Named `documentDigests` in data model section 10.1; the bindings and WeBuild
    /// cs-03 examples use `documentInfos`.
    #[serde(rename = "documentInfos")]
    pub document_infos: Vec<DocumentInfo>,
    /// Hash algorithm used for the hashes in `documentInfos` and for computing the
    /// `qesApproval` response value (section 7.2)
    #[serde(rename = "hashAlgorithmOID")]
    pub hash_algorithm: HashAlgorithm,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::super::data_model::AccessControlMethod;
    use super::*;

    #[test]
    fn qes_approval_request_example_from_data_model_bindings_roundtrips() {
        // Section 7.1.2 of the data model bindings.
        let example = json!({
            "type": "https://cloudsignatureconsortium.org/2025/qes-approval",
            "credential_ids": ["xyz123"],
            "numSignatures": 2,
            "signatureQualifier": "eu_eidas_qes",
            "documentInfos": [
                {
                    "label": "Example Contract",
                    "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                    "hashType": "sodr",
                    "access": { "type": "OTP", "oneTimePassword": "51623" },
                    "href": "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
                    "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
                },
                {
                    "label": "Example Terms of Service",
                    "hash": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
                    "hashType": "sodr",
                    "access": { "type": "public" },
                    "href": "https://public.rp-cdn.example/terms-and-conditions.pdf",
                    "checksum": "sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="
                },
                {
                    "label": "Example Invoice",
                    "hash": "nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ=",
                    "hashType": "sodr",
                    "access": { "type": "OTP", "oneTimePassword": "83920" },
                    "href": "https://protected.rp.example/invoice-2025-07.pdf?token=jk47ns88sna9a",
                    "checksum": "sha256-nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ="
                }
            ],
            "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
        });

        let request: QesApprovalRequest = serde_json::from_value(example.clone()).unwrap();

        assert_eq!(request.r#type, QES_APPROVAL_TRANSACTION_DATA_TYPE);
        assert_eq!(request.credential_ids, vec!["xyz123"]);
        assert_eq!(request.num_signatures, 2);
        assert_eq!(
            request.signature_qualifier,
            Some(SignatureQualifier::EuEidasQes)
        );
        assert_eq!(request.credential_id, None);
        assert_eq!(request.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(request.document_infos.len(), 3);

        let contract = &request.document_infos[0];
        assert_eq!(contract.label.as_deref(), Some("Example Contract"));
        assert_eq!(contract.hash_type.as_deref(), Some("sodr"));
        assert_eq!(
            contract.access,
            Some(AccessControlMethod::Otp {
                one_time_password: "51623".to_string()
            })
        );

        assert_eq!(serde_json::to_value(&request).unwrap(), example);
    }
}
