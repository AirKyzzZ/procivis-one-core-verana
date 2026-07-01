use serde::{Deserialize, Serialize};

use crate::provider::trust_list_subscriber::cert_index::CertIndex;

/// A resolved TS 119 612 trust-service entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TslServiceEntry {
    pub service_name: String,
    pub service_type_identifier: String,
    pub service_status: String,
}

/// Aggregated, signature-verified index built by the LOTL resolver and cached.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PreprocessedLotl {
    pub entries: Vec<TslServiceEntry>,
    /// Map of SKI / fingerprint to indices into `entries`.
    pub cert_index: CertIndex,
    /// Member-list URLs handed to delegate subscribers at resolve time.
    pub delegated_member_urls: Vec<String>,
}
