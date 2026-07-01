use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use standardized_types::etsi_119_602::TrustedEntityInformation;

use crate::model::trust_list_role::TrustListRoleEnum;
use crate::provider::trust_list_subscriber::cert_index::CertIndex;

/// A trusted entity together with the role derived from its source list, so a
/// roleless aggregate (e.g. one built by following `PointersToOtherLoTE`) can be
/// gated per entity at resolve time.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct LoteEntity {
    pub info: TrustedEntityInformation,
    pub derived_role: Option<TrustListRoleEnum>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub(super) struct PreprocessedLote {
    /// Role shared by all entities, else `None` (roleless aggregate, gated per entity).
    pub role: Option<TrustListRoleEnum>,
    /// Trusted entities (incl. pointed-to LoTEs), each tagged with its source role.
    pub trusted_entities: Vec<LoteEntity>,
    /// Map of SKI / fingerprint to indices into `trusted_entities`.
    pub cert_index: CertIndex,
    /// Map of DER-encoded public keys to indices into `trusted_entities`.
    #[serde(default)]
    pub public_keys: HashMap<String, Vec<usize>>,
}
