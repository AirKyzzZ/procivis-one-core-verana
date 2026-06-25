use standardized_types::xades::XMLDSIG_NS;

mod canonicalizer;
pub(crate) mod escape;
pub(crate) mod render;

pub(crate) use canonicalizer::SkipElement;

/// XML Canonicalization 1.0 algorithm (both "without comments").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum C14nMode {
    /// Exclusive (`http://www.w3.org/2001/10/xml-exc-c14n#`).
    Exclusive,
    /// Inclusive (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`).
    Inclusive,
}

#[derive(Debug, thiserror::Error)]
pub enum C14nError {
    #[error("XML parse error: {0}")]
    XmlParse(#[from] roxmltree::Error),
    #[error("Element not found: {0}")]
    ElementNotFound(String),
}

/// Canonicalize a full document with `mode`, optionally skipping elements
/// matching `skip` (used for the enveloped-signature transform).
pub(crate) fn canonicalize(
    xml: &str,
    mode: C14nMode,
    skip: Option<SkipElement<'_>>,
) -> Result<Vec<u8>, C14nError> {
    let doc = roxmltree::Document::parse(xml)?;
    canonicalizer::canonicalize_doc(&doc, mode, skip)
}

/// Canonicalize the subtree of the element whose `Id` attribute equals `id`
/// (same-document `URI="#id"` reference), optionally skipping elements matching
/// `skip` (e.g. an enveloped signature nested in that subtree). The subtree is
/// canonicalized with its in-scope ancestor namespaces.
pub(crate) fn canonicalize_by_id(
    xml: &str,
    mode: C14nMode,
    id: &str,
    skip: Option<SkipElement<'_>>,
) -> Result<Vec<u8>, C14nError> {
    let doc = roxmltree::Document::parse(xml)?;
    let target = doc
        .descendants()
        .find(|n| n.is_element() && n.attribute("Id") == Some(id))
        .ok_or_else(|| C14nError::ElementNotFound(format!("element with Id={id}")))?;
    canonicalizer::canonicalize_subtree(&target, mode, skip)
}

/// Canonicalize a subtree identified by namespace, local name, and optional Id,
/// searching within the ds:Signature element identified by `signature_id`.
pub(crate) fn canonicalize_signature_subtree(
    xml: &str,
    mode: C14nMode,
    signature_id: Option<&str>,
    child_ns: &str,
    child_name: &str,
) -> Result<Vec<u8>, C14nError> {
    let doc = roxmltree::Document::parse(xml)?;

    let sig = doc
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(XMLDSIG_NS)
                && n.tag_name().name() == "Signature"
                && signature_id.is_none_or(|id| n.attribute("Id") == Some(id))
        })
        .ok_or_else(|| C14nError::ElementNotFound("ds:Signature".into()))?;

    let target = sig
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(child_ns)
                && n.tag_name().name() == child_name
        })
        .ok_or_else(|| C14nError::ElementNotFound(format!("{child_ns}:{child_name}")))?;

    canonicalizer::canonicalize_subtree(&target, mode, None)
}
