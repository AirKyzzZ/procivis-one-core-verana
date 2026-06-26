use standardized_types::xades::XMLDSIG_NS;

pub(crate) mod escape;
mod exclusive;
pub(crate) mod render;

pub(crate) use exclusive::SkipElement;

#[derive(Debug, thiserror::Error)]
pub enum C14nError {
    #[error("XML parse error: {0}")]
    XmlParse(#[from] roxmltree::Error),
    #[error("Element not found: {0}")]
    ElementNotFound(String),
}

/// Exclusive XML Canonicalization 1.0 (without comments) of a full document,
/// optionally skipping elements matching `skip`.
pub(crate) fn canonicalize(xml: &str, skip: Option<SkipElement<'_>>) -> Result<Vec<u8>, C14nError> {
    let doc = roxmltree::Document::parse(xml)?;
    exclusive::canonicalize_doc(&doc, skip)
}

/// Exclusive C14N (without comments) of the element whose `Id` attribute equals
/// `id` (same-document `URI="#id"` reference). The subtree is canonicalized with
/// its in-scope ancestor namespaces, as the existing subtree canonicalizer does.
pub(crate) fn canonicalize_by_id(xml: &str, id: &str) -> Result<Vec<u8>, C14nError> {
    let doc = roxmltree::Document::parse(xml)?;
    let target = doc
        .descendants()
        .find(|n| n.is_element() && n.attribute("Id") == Some(id))
        .ok_or_else(|| C14nError::ElementNotFound(format!("element with Id={id}")))?;
    exclusive::canonicalize_subtree(&target)
}

/// Canonicalize a subtree identified by namespace, local name, and optional Id,
/// searching within the ds:Signature element identified by `signature_id`.
pub(crate) fn canonicalize_signature_subtree(
    xml: &str,
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

    exclusive::canonicalize_subtree(&target)
}
