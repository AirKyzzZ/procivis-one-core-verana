//! XAdES Baseline B-B enveloped signatures (ETSI EN 319 132-1, ETSI TS 119 602 Annex H.4).

mod c14n;
pub(crate) mod error;
mod signature;

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64, Decoder};
use one_crypto::{CryptoProvider, Hasher};
use serde::de::DeserializeOwned;
use standardized_types::xades::{
    self, EXC_C14N, SHA256_DIGEST_URI, SHA512_DIGEST_URI, SIGNED_PROPERTIES_TYPE, XADES_NS,
    XMLDSIG_NS,
};
use time::Duration;

use self::error::Error;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::proto::certificate_validator::{CertificateValidationOptions, CertificateValidator};
use crate::provider::credential_formatter::model::SignatureProvider;

impl TryFrom<KeyAlgorithmType> for xades::SignatureSuite {
    type Error = Error;

    fn try_from(value: KeyAlgorithmType) -> Result<Self, Self::Error> {
        match value {
            KeyAlgorithmType::Ecdsa => Ok(xades::SignatureSuite::ES256),
            KeyAlgorithmType::Eddsa => Ok(xades::SignatureSuite::EdDSA),
            _ => Err(Error::UnsupportedSuite(value.to_string())),
        }
    }
}

#[async_trait]
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait XAdESProto: Send + Sync {
    async fn create_enveloped_signature(
        &self,
        unsigned_xml: &str,
        signer: &dyn SignatureProvider,
        x5c: Vec<String>,
    ) -> Result<String, Error>;

    async fn verify_enveloped_signature(
        &self,
        signed: &XAdESEnvelopedSignature,
        clock_leeway: Duration,
    ) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct XAdESEnvelopedSignature {
    pub(crate) signature: xades::Signature,
    pub(crate) unverified_document: String,
}

pub struct XAdES {
    crypto_provider: Arc<dyn CryptoProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl XAdES {
    pub fn new(
        crypto_provider: Arc<dyn CryptoProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            crypto_provider,
            certificate_validator,
        }
    }
}

#[async_trait]
impl XAdESProto for XAdES {
    async fn create_enveloped_signature(
        &self,
        unsigned_xml: &str,
        signer: &dyn SignatureProvider,
        x5c: Vec<String>,
    ) -> Result<String, Error> {
        let parsed_document = roxmltree::Document::parse(unsigned_xml)?;

        if parsed_document.descendants().any(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(XMLDSIG_NS)
                && n.tag_name().name() == "Signature"
        }) {
            return Err(Error::InvalidDocument(
                "unexpected ds:Signature node".to_string(),
            ));
        };

        let xades_suite: xades::SignatureSuite = signer
            .get_key_algorithm()
            .error_while("getting key algorithm type")?
            .try_into()
            .error_while("generating signature")?;

        let hasher = resolve_hasher(&*self.crypto_provider, xades_suite.hash_alg_uri())
            .error_while("generating signature")?;

        let signing_certificate = x5c
            .first()
            .ok_or(Error::EmptyCertificateChain)
            .error_while("generating signature")?;

        let signature = signature::build_signature(
            &xades_suite,
            &x5c,
            unsigned_xml,
            &*hasher,
            signer,
            signing_certificate,
        )
        .await
        .error_while("generating signature")?;

        let sig_xml = quick_xml::se::to_string(&signature)?;

        // root.range() skips any XML declaration / PIs before the root element
        let root = parsed_document.root_element();
        let root_xml = &unsigned_xml[root.range().start..root.range().end];
        let insert_pos = root_xml.rfind("</").ok_or(Error::InvalidDocument(
            "missing root closing tag".to_string(),
        ))?;

        let signed_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}{}{}",
            &root_xml[..insert_pos],
            sig_xml,
            &root_xml[insert_pos..],
        );

        Ok(signed_xml)
    }

    async fn verify_enveloped_signature(
        &self,
        signed: &XAdESEnvelopedSignature,
        clock_leeway: Duration,
    ) -> Result<(), Error> {
        signed
            .verify_signature(
                &*self.crypto_provider,
                &*self.certificate_validator,
                clock_leeway,
            )
            .await
    }
}

#[derive(Debug)]
pub(crate) struct XAdESSignedXML<T> {
    envelope: XAdESEnvelopedSignature,
    pub(crate) content: T,
}

// TS 119 602 §6.8 subject DN matching is a LoTE-level policy check,
// should handled by the trust-list subscriber rather than the XAdES verifier.
impl<T> XAdESSignedXML<T>
where
    T: DeserializeOwned,
{
    pub fn decompose_document(xml: &str) -> Result<XAdESSignedXML<T>, Error> {
        let parsed_document = roxmltree::Document::parse(xml)?;
        let signature_node = parsed_document
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.tag_name().namespace() == Some(XMLDSIG_NS)
                    && n.tag_name().name() == "Signature"
            })
            .ok_or(Error::MissingEnvelopedSignature)
            .error_while("decomposing signed document")?;

        let signature_node_position = signature_node.range();

        let signature = &xml[signature_node_position.start..signature_node_position.end];

        let content_xml = format!(
            "{}{}",
            &xml[..signature_node_position.start],
            &xml[signature_node_position.end..]
        );

        let signature: xades::Signature = quick_xml::de::from_str(signature)?;

        Ok(Self {
            envelope: XAdESEnvelopedSignature {
                signature,
                unverified_document: xml.to_string(),
            },
            content: quick_xml::de::from_str(&content_xml)?,
        })
    }

    pub fn envelope(&self) -> &XAdESEnvelopedSignature {
        &self.envelope
    }
}

impl XAdESEnvelopedSignature {
    pub(crate) async fn verify_signature(
        &self,
        crypto_provider: &dyn CryptoProvider,
        certificate_validator: &dyn CertificateValidator,
        clock_leeway: Duration,
    ) -> Result<(), Error> {
        let sig = &self.signature;
        let signature_id = sig.id.as_deref();
        let signed_info = &sig.signed_info;
        let qualifying_props = &sig.object.qualifying_properties;
        let signed_sig_props = &qualifying_props
            .signed_properties
            .signed_signature_properties;

        // EN 319 132-1 §4.3.1
        let expected_target = signature_id.map(|id| format!("#{id}"));
        if expected_target.as_deref() != Some(qualifying_props.target.as_str()) {
            return Err(Error::InvalidSignature(format!(
                "QualifyingProperties Target mismatch: expected {}, got {}",
                expected_target
                    .as_deref()
                    .unwrap_or("<missing ds:Signature Id>"),
                qualifying_props.target,
            )));
        }

        // EN 319 132-1 §5.2.1
        let now = crate::clock::now_utc();
        if signed_sig_props.signing_time > now + clock_leeway {
            return Err(Error::SigningTimeInFuture);
        }

        if signed_info.canonicalization_method.algorithm != EXC_C14N {
            return Err(Error::InvalidSignature(format!(
                "Unsupported canonicalization algorithm {}, expected {EXC_C14N}",
                signed_info.canonicalization_method.algorithm
            )));
        }

        if xades::SignatureSuite::try_from_sig_uri(&signed_info.signature_method.algorithm)
            .is_none()
        {
            return Err(Error::UnsupportedSuite(format!(
                "unknown SignatureMethod algorithm: {}",
                signed_info.signature_method.algorithm
            )));
        }

        let references = &signed_info.references;

        // EN 319 132-1 §6.3 (b)
        if references.len() < 2 {
            return Err(Error::InvalidSignature(format!(
                "Expected at least two ds:Reference entries, got {}",
                references.len(),
            )));
        }

        // TS 119 602 H.4: document reference with URI=""
        let doc_ref = references
            .iter()
            .find(|r| r.uri.is_empty())
            .ok_or(Error::MissingReference("root document".to_string()))?;

        let sp_ref = references
            .iter()
            .find(|r| r.r#type.as_deref() == Some(SIGNED_PROPERTIES_TYPE))
            .ok_or(Error::MissingReference("SignedProperties".to_string()))?;

        // EN 319 132-1 §4.4.2
        let sp_id = &qualifying_props.signed_properties.id;
        let expected_sp_uri = format!("#{sp_id}");
        if sp_ref.uri != expected_sp_uri {
            return Err(Error::InvalidSignature(format!(
                "SignedProperties reference URI mismatch: expected {expected_sp_uri}, got {}",
                sp_ref.uri,
            )));
        }

        // EN 319 132-1 §5.2.6
        let data_obj_fmt = &qualifying_props
            .signed_properties
            .signed_data_object_properties
            .data_object_format;
        let doc_ref_uri = doc_ref
            .id
            .as_ref()
            .map(|id| format!("#{id}"))
            .unwrap_or_default();
        if data_obj_fmt.object_reference != doc_ref_uri {
            return Err(Error::InvalidSignature(format!(
                "DataObjectFormat ObjectReference mismatch: expected {doc_ref_uri}, got {}",
                data_obj_fmt.object_reference,
            )));
        }
        if data_obj_fmt.mime_type.is_empty() {
            return Err(Error::InvalidSignature(
                "DataObjectFormat MimeType is empty".to_string(),
            ));
        }

        // EN 319 132-1 §6.3 (f,g)
        let sig_exclusion = apply_document_transforms(&doc_ref.transforms.transforms)
            .error_while("validating document reference transforms")?;

        if sp_ref.transforms.transforms != [xades::Transform::ExcC14n] {
            return Err(Error::InvalidTransformsInReference(format!(
                "expected [ExcC14n] for SignedProperties, got {:?}",
                sp_ref.transforms.transforms,
            )));
        }

        let doc_hasher = resolve_hasher(crypto_provider, &doc_ref.digest_method.algorithm)
            .error_while("resolving document digest algorithm")?;
        let skip_id = match sig_exclusion {
            SignatureExclusion::ById => signature_id,
            SignatureExclusion::All => None,
        };
        let doc_canonical = c14n::canonicalize(
            &self.unverified_document,
            Some(c14n::SkipElement {
                namespace: XMLDSIG_NS,
                local_name: "Signature",
                id: skip_id,
            }),
        )
        .map_err(Error::from)
        .error_while("canonicalizing document")?;
        if doc_hasher.hash_base64(&doc_canonical)? != doc_ref.digest_value {
            return Err(Error::IncorrectDigest("Root document".to_string()));
        }

        let sp_hasher = resolve_hasher(crypto_provider, &sp_ref.digest_method.algorithm)
            .error_while("resolving SignedProperties digest algorithm")?;
        let sp_canonical = c14n::canonicalize_signature_subtree(
            &self.unverified_document,
            signature_id,
            XADES_NS,
            "SignedProperties",
        )
        .map_err(Error::from)
        .error_while("canonicalizing SignedProperties")?;
        if sp_hasher.hash_base64(&sp_canonical)? != sp_ref.digest_value {
            return Err(Error::IncorrectDigest("SignedProperties".to_string()));
        }

        // EN 319 132-1 §5.2.2: match SigningCertificateV2 digest against KeyInfo
        let signing_chain = self
            .find_signing_certificate_chain(crypto_provider)
            .error_while("matching signing certificate")?;

        // Chain is leaf-first within X509Data (EN 319 132-1 §6.3 (b,c))
        let pem_chain = x5c_into_pem_chain(signing_chain).error_while("parsing signer X509Data")?;

        let parsed = certificate_validator
            .parse_pem_chain(
                &pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
            .error_while("validating signer certificate chain")?;

        let sig_value_bytes = Base64::decode_to_vec(sig.signature_value.value.trim(), None)
            .map_err(Error::from)
            .error_while("decoding signature value")?;

        let si_canonical = c14n::canonicalize_signature_subtree(
            &self.unverified_document,
            signature_id,
            XMLDSIG_NS,
            "SignedInfo",
        )
        .map_err(Error::from)
        .error_while("canonicalizing SignedInfo")?;

        parsed
            .public_key
            .verify(&si_canonical, &sig_value_bytes)
            .error_while("verifying document signature")?;

        Ok(())
    }

    fn find_signing_certificate_chain(
        &self,
        crypto_provider: &dyn CryptoProvider,
    ) -> Result<&[String], Error> {
        let sig = &self.signature;
        let signed_sig_props = &sig
            .object
            .qualifying_properties
            .signed_properties
            .signed_signature_properties;

        // EN 319 132-1 §5.2.2
        let cert_ref = signed_sig_props
            .signing_certificate_v2
            .certs
            .first()
            .ok_or_else(|| {
                Error::InvalidSignature(
                    "SigningCertificateV2 contains no Cert elements".to_string(),
                )
            })?;

        let cert_hasher = resolve_hasher(
            crypto_provider,
            &cert_ref.cert_digest.digest_method.algorithm,
        )?;

        let expected_digest = &cert_ref.cert_digest.digest_value;

        let [x509_entry] = &sig.key_info.x509_data[..] else {
            return Err(Error::InvalidSignature(format!(
                "ds:X509Data expected to contain 1 entry, found {}",
                sig.key_info.x509_data.len()
            )));
        };

        let leaf = x509_entry.x509_certificates.first().ok_or_else(|| {
            Error::InvalidSignature("ds:X509Data entry contains no certificates".to_string())
        })?;

        if cert_hasher.hash_base64(&Base64::decode_to_vec(leaf, None)?)? != *expected_digest {
            return Err(Error::SigningCertificateNotFound(expected_digest.clone()));
        }

        Ok(x509_entry.x509_certificates.as_ref())
    }
}

/// How the ds:Signature element should be excluded during document digest computation.
enum SignatureExclusion {
    /// Enveloped-signature: skip the signature matching the given Id.
    ById,
    /// XPath Filter 2.0 subtract: skip all ds:Signature elements.
    All,
}

/// Interpret the document reference transform chain.
fn apply_document_transforms(transforms: &[xades::Transform]) -> Result<SignatureExclusion, Error> {
    use xades::Transform::*;
    use xades::XPathFilter2Op;
    match transforms {
        [EnvelopedSignature, ExcC14n] => Ok(SignatureExclusion::ById),

        [XPathFilter2(ops), ExcC14n] => {
            let subtract = ops
                .iter()
                .find_map(|op| match op {
                    XPathFilter2Op::Subtract(xpath) => Some(xpath.as_str()),
                    _ => None,
                })
                .ok_or_else(|| {
                    Error::InvalidTransformsInReference(
                        "XPath Filter 2.0 has no subtract operation".to_string(),
                    )
                })?;

            let xpath = subtract.trim();
            if xpath.ends_with("Signature") && xpath.contains("descendant") {
                Ok(SignatureExclusion::All)
            } else {
                Err(Error::InvalidTransformsInReference(format!(
                    "unsupported XPath Filter 2.0 expression: {xpath}"
                )))
            }
        }

        other => Err(Error::InvalidTransformsInReference(format!(
            "unsupported transform chain: {other:?}"
        ))),
    }
}

fn resolve_hasher(
    crypto_provider: &dyn CryptoProvider,
    digest_uri: &str,
) -> Result<std::sync::Arc<dyn Hasher>, Error> {
    let name = match digest_uri {
        SHA256_DIGEST_URI => "sha-256",
        SHA512_DIGEST_URI => "sha-512",
        other => {
            return Err(Error::UnsupportedSuite(format!(
                "unsupported digest algorithm URI: {other}"
            )));
        }
    };
    Ok(crypto_provider.get_hasher(name)?)
}

#[cfg(test)]
mod test;
