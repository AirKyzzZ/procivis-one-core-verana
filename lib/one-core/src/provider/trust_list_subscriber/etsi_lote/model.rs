use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use standardized_types::etsi_119_602::TrustedEntityInformation;
use standardized_types::x509::KeyIdentifier;

use crate::model::trust_list_role::TrustListRoleEnum;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct CertificateEntry {
    /// index into `trust_entities`
    pub idx: usize,
    pub pem: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PreprocessedLote {
    /// Role of this LoTE
    pub role: Option<TrustListRoleEnum>,
    /// List of all trusted entities in the LoTE.
    pub trusted_entities: Vec<TrustedEntityInformation>,

    /// Map of cert fingerprints to indices into `trust_entities`
    pub certificate_fingerprints: HashMap<String, usize>,
    #[serde(default)]
    pub certificate_by_subject_key_identifier: HashMap<KeyIdentifier, CertificateEntry>,

    /// Map of DER-encoded public keys to indices into `trust_entities`
    #[serde(default)]
    pub public_keys: HashMap<String, usize>,
}
