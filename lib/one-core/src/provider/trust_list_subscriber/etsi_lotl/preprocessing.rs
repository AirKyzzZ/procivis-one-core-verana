use standardized_types::etsi_119_612::ServiceStatus;
use standardized_types::etsi_119_612::xml::{DigitalId, TspService};

use super::model::{PreprocessedLotl, TslServiceEntry};
use crate::proto::certificate_validator::{CertificateValidationOptions, CertificateValidator};

/// Build the LOTL lookup index from a flat list of member-TSL services.
pub async fn preprocess_services(
    services: Vec<TspService>,
    certificate_validator: &dyn CertificateValidator,
) -> Result<PreprocessedLotl, crate::provider::trust_list_subscriber::error::TrustListSubscriberError>
{
    let mut index = PreprocessedLotl::default();

    for service in services {
        let info = service.service_information;
        // only index trusted/active services
        if !matches!(
            info.service_status,
            ServiceStatus::Granted | ServiceStatus::RecognisedAtNationalLevel
        ) {
            continue;
        }
        let entry = TslServiceEntry {
            service_name: info
                .service_name
                .names
                .first()
                .map(|n| n.value.clone())
                .unwrap_or_default(),
            service_type_identifier: info.service_type_identifier.to_string(),
            service_status: info.service_status.to_string(),
        };
        let entry_idx = index.entries.len();
        index.entries.push(entry);

        for DigitalId {
            x509_certificate, ..
        } in info.service_digital_identity.digital_ids
        {
            // only index certificate-bearing identities; AKI→CA matching needs the
            // CA PEM, which a bare <X509SKI> lacks
            if let Some(cert_b64) = x509_certificate
                && let Ok(pem) =
                    crate::mapper::x509::x5c_into_pem_chain(std::slice::from_ref(&cert_b64))
            {
                // no_validation here; the chain/revocation check runs at match time
                if let Ok(parsed) = certificate_validator
                    .parse_pem_chain(&pem, CertificateValidationOptions::no_validation())
                    .await
                {
                    let ski = crate::mapper::x509::pem_to_subject_key_identifier(&pem)
                        .ok()
                        .flatten();
                    index
                        .cert_index
                        .insert(parsed.attributes.fingerprint, ski, pem, entry_idx);
                }
            }
        }
    }
    Ok(index)
}
