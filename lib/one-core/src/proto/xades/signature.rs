//! XAdES enveloped signature construction.

use ct_codecs::{Base64, Decoder, Encoder};
use one_crypto::Hasher;
use standardized_types::xades::{
    AlgorithmIdentifier, Cert, CertDigest, DataObjectFormat, EXC_C14N, KeyInfo, Object,
    QualifyingProperties, Reference, SIGNED_PROPERTIES_TYPE, Signature, SignatureSuite,
    SignatureValue, SignedDataObjectProperties, SignedInfo, SignedProperties,
    SignedSignatureProperties, SigningCertificateV2, Transform, Transforms, X509Data, XADES_NS,
    XMLDSIG_NS,
};

use super::c14n;
use super::error::Error;
use crate::provider::credential_formatter::model::SignatureProvider;

pub(super) fn build_signed_properties(
    signing_certificate_hash: String,
    xades_suite: &SignatureSuite,
    nonce: &str,
) -> SignedProperties {
    // EN 319 132-1 §6.3 (i,j): IssuerSerialV2 and URI omitted for baseline
    let certificate_reference = SigningCertificateV2 {
        certs: vec![Cert {
            cert_digest: CertDigest {
                digest_method: AlgorithmIdentifier {
                    algorithm: xades_suite.hash_alg_uri().to_string(),
                },
                digest_value: signing_certificate_hash,
            },
            issuer_serial_v2: None,
        }],
    };

    let signed_signature_properties = SignedSignatureProperties {
        signing_time: crate::clock::now_utc(),
        signing_certificate_v2: certificate_reference,
    };

    SignedProperties {
        xmlns_xades: XADES_NS.to_string(),
        xmlns_ds: XMLDSIG_NS.to_string(),
        id: format!("xades-id-{nonce}"),
        signed_signature_properties,
        signed_data_object_properties: SignedDataObjectProperties {
            data_object_format: DataObjectFormat {
                object_reference: format!("#r-id-{nonce}"),
                mime_type: "text/xml".to_string(),
            },
        },
    }
}

pub(super) fn build_signed_info(
    xades_suite: &SignatureSuite,
    nonce: &str,
    document_hash: &str,
    signed_properties_hash: &str,
) -> SignedInfo {
    // TS 119 602 H.4: enveloped-signature then exc-c14n
    let transforms = vec![Transform::EnvelopedSignature, Transform::ExcC14n];

    let digest_method = AlgorithmIdentifier {
        algorithm: xades_suite.hash_alg_uri().to_string(),
    };

    // TS 119 602 H.4: URI="" refers to the entire document
    let document_reference = Reference {
        id: Some(format!("r-id-{nonce}")),
        uri: String::new(),
        r#type: None,
        transforms: Some(Transforms { transforms }),
        digest_method: digest_method.clone(),
        digest_value: document_hash.to_string(),
    };

    // EN 319 132-1 §4.4.2: exc-c14n only (no enveloped-signature)
    let signed_properties_reference = Reference {
        id: None,
        uri: format!("#xades-id-{nonce}"),
        r#type: Some(SIGNED_PROPERTIES_TYPE.to_string()),
        transforms: Some(Transforms {
            transforms: vec![Transform::ExcC14n],
        }),
        digest_method,
        digest_value: signed_properties_hash.to_string(),
    };

    SignedInfo {
        xmlns_ds: XMLDSIG_NS.to_string(),
        canonicalization_method: AlgorithmIdentifier {
            algorithm: EXC_C14N.to_string(),
        },
        signature_method: AlgorithmIdentifier {
            algorithm: xades_suite.signature_alg_uri().to_string(),
        },
        references: vec![document_reference, signed_properties_reference],
    }
}

pub(super) async fn build_signature(
    xades_suite: &SignatureSuite,
    x5c: &[String],
    document: &str,
    hasher: &dyn Hasher,
    signer: &dyn SignatureProvider,
    signing_cert: &str,
) -> Result<Signature, Error> {
    let nonce = uuid::Uuid::new_v4().to_string();

    let document_hash = hasher.hash_base64(&c14n::canonicalize(document, None)?)?;
    let signing_certificate_hash = {
        let cert_der = Base64::decode_to_vec(signing_cert, None)?;
        hasher.hash_base64(&cert_der)?
    };

    let signed_properties = build_signed_properties(signing_certificate_hash, xades_suite, &nonce);

    let signed_properties_hash = {
        let sp_xml = quick_xml::se::to_string(&signed_properties)?;
        hasher.hash_base64(&c14n::canonicalize(&sp_xml, None)?)?
    };

    let signed_info =
        build_signed_info(xades_suite, &nonce, &document_hash, &signed_properties_hash);

    let signature = {
        let si_xml = quick_xml::se::to_string(&signed_info)?;
        let si_canonical = c14n::canonicalize(&si_xml, None)?;

        let signature = signer.sign(&si_canonical).await?;
        Base64::encode_to_string(&signature)?
    };

    let signature_id = format!("id-{nonce}");

    Ok(Signature {
        xmlns_ds: XMLDSIG_NS.to_string(),
        id: Some(signature_id.clone()),
        signed_info,
        signature_value: SignatureValue {
            id: Some(format!("value-id-{nonce}")),
            value: signature,
        },
        key_info: KeyInfo {
            x509_data: vec![X509Data {
                x509_certificates: x5c.to_vec(),
            }],
        },
        object: Object {
            qualifying_properties: QualifyingProperties {
                xmlns_xades: XADES_NS.to_string(),
                target: format!("#{signature_id}"),
                signed_properties,
            },
        },
    })
}
