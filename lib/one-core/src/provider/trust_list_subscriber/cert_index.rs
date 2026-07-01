use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use standardized_types::x509::KeyIdentifier;

use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_to_authority_key_identifiers;
use crate::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator,
};
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CertEntry {
    pub idx: usize,
    pub pem: String,
}

/// Certificate matching index shared by the LoTL and LoTE subscribers, mapping a
/// CA SubjectKeyIdentifier and a leaf fingerprint to the entries they back.
/// Multi-valued so a CA backing services of different roles is not collapsed.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct CertIndex {
    pub ca_ski_to_entries: HashMap<KeyIdentifier, Vec<CertEntry>>,
    pub fingerprint_to_entries: HashMap<String, Vec<usize>>,
}

impl CertIndex {
    /// Index a certificate against entry `idx`, by fingerprint and (if present) SKI.
    pub fn insert(
        &mut self,
        fingerprint: String,
        subject_key_identifier: Option<KeyIdentifier>,
        pem: String,
        idx: usize,
    ) {
        self.fingerprint_to_entries
            .entry(fingerprint)
            .or_default()
            .push(idx);
        if let Some(ski) = subject_key_identifier {
            self.ca_ski_to_entries
                .entry(ski)
                .or_default()
                .push(CertEntry { idx, pem });
        }
    }

    /// Merge `other` in, shifting its entry indices by `offset`.
    pub fn extend_offset(&mut self, other: CertIndex, offset: usize) {
        for (ski, entries) in other.ca_ski_to_entries {
            self.ca_ski_to_entries
                .entry(ski)
                .or_default()
                .extend(entries.into_iter().map(|entry| CertEntry {
                    idx: entry.idx + offset,
                    pem: entry.pem,
                }));
        }
        for (fingerprint, indices) in other.fingerprint_to_entries {
            self.fingerprint_to_entries
                .entry(fingerprint)
                .or_default()
                .extend(indices.into_iter().map(|idx| idx + offset));
        }
    }

    /// Entries a PEM chain matches: AKI→CA-SKI (chain-consistency checked), else
    /// by leaf fingerprint.
    pub async fn match_chain(
        &self,
        pem_chain: &str,
        certificate_validator: &dyn CertificateValidator,
    ) -> Result<Vec<usize>, TrustListSubscriberError> {
        let chain_authority_key_identifiers =
            pem_chain_to_authority_key_identifiers(pem_chain).error_while("parsing PEM chain")?;

        let mut matched: Vec<usize> = Vec::new();
        for aki in &chain_authority_key_identifiers {
            let Some(entries) = self.ca_ski_to_entries.get(aki) else {
                continue;
            };
            for entry in entries {
                match certificate_validator
                    .validate_chain_against_ca_chain(
                        pem_chain,
                        &entry.pem,
                        CertificateValidationOptions::signature_and_revocation(None),
                        CertSelection::Leaf,
                    )
                    .await
                {
                    Ok(_) => {
                        if !matched.contains(&entry.idx) {
                            matched.push(entry.idx);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Trust entity found via AKI, but consistency checking failed");
                    }
                }
            }
        }

        if matched.is_empty() {
            let parsed = certificate_validator
                .parse_pem_chain(
                    pem_chain,
                    CertificateValidationOptions::signature_and_revocation(None),
                )
                .await
                .error_while("parsing input PEM chain")?;
            if let Some(indices) = self
                .fingerprint_to_entries
                .get(&parsed.attributes.fingerprint)
            {
                matched.extend(indices.iter().copied());
            }
        }

        Ok(matched)
    }
}
