use one_core::model::certificate::{Certificate, CertificateState};
use one_core::provider::credential_formatter::model::CredentialData;
use one_core::util::test_mdoc::format_mdoc_credential as format_mdoc;
use rcgen::CertificateParams;
use shared_types::SerializedCredential;
use uuid::Uuid;

use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};

pub(crate) async fn format_mdoc_credential(
    mut credential_data: CredentialData,
    params: serde_json::Value,
) -> SerializedCredential {
    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, eddsa::Key);
    let cert = create_cert(
        &mut CertificateParams::default(),
        ecdsa::Key,
        &ca_issuer,
        &ca_params,
    );
    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    // the formatter will only use the chain
    credential_data.issuer_certificate = Some(Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: Uuid::new_v4().into(),
        organisation: None,
        created_date: one_core::clock::now_utc(),
        last_modified: one_core::clock::now_utc(),
        expiry_date: one_core::clock::now_utc(),
        name: "".to_string(),
        chain,
        fingerprint: "".to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
        deleted_at: None,
    });

    format_mdoc(credential_data, params, ecdsa::signature_provider()).await
}
