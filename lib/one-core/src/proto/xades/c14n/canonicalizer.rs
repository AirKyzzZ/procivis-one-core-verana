//! XML Canonicalization 1.0 ("without comments"), both exclusive
//! (`xml-exc-c14n#`) and inclusive (`REC-xml-c14n-20010315`), selected by
//! `C14nMode`. The two share everything except which namespace declarations
//! each element renders (see `namespace_decls`).

use std::collections::{BTreeMap, HashSet};

use super::render::{Attr, NsDecl};
use super::{C14nError, C14nMode, escape};

/// Predicate for excluding elements during canonicalization.
pub(crate) struct SkipElement<'a> {
    pub namespace: &'a str,
    pub local_name: &'a str,
    /// If `Some`, only skip the element with this `Id` attribute.
    /// If `None`, skip all matching elements.
    pub id: Option<&'a str>,
}

struct C14nContext<'a> {
    mode: C14nMode,
    skip: Option<SkipElement<'a>>,
}

fn resolve_prefix<'a>(node: roxmltree::Node<'a, '_>, uri: &str) -> Option<&'a str> {
    if uri == "http://www.w3.org/XML/1998/namespace" {
        return Some("xml");
    }
    std::iter::once(node).chain(node.ancestors()).find_map(|n| {
        n.namespaces()
            .find(|ns| ns.uri() == uri)
            .and_then(|ns| ns.name())
    })
}

fn element_prefix(node: roxmltree::Node<'_, '_>) -> String {
    node.tag_name()
        .namespace()
        .and_then(|uri| resolve_prefix(node, uri))
        .unwrap_or("")
        .to_owned()
}

fn qualified_element_name(node: roxmltree::Node<'_, '_>) -> String {
    let local = node.tag_name().name();
    let prefix = element_prefix(node);
    if prefix.is_empty() {
        local.to_owned()
    } else {
        format!("{prefix}:{local}")
    }
}

fn attribute_prefix(node: roxmltree::Node<'_, '_>, attr: &roxmltree::Attribute<'_, '_>) -> String {
    match attr.namespace() {
        Some("http://www.w3.org/XML/1998/namespace") => "xml".to_owned(),
        Some(uri) => resolve_prefix(node, uri).unwrap_or("").to_owned(),
        None => String::new(),
    }
}

fn collect_inscope_namespaces(node: roxmltree::Node<'_, '_>) -> BTreeMap<String, String> {
    let mut ns_stack: Vec<Vec<(String, String)>> = Vec::new();
    let mut current = Some(node);
    while let Some(n) = current {
        if n.is_element() {
            let level: Vec<_> = n
                .namespaces()
                .map(|ns| (ns.name().unwrap_or("").to_owned(), ns.uri().to_owned()))
                .collect();
            ns_stack.push(level);
        }
        current = n.parent();
    }
    let mut result = BTreeMap::new();
    for level in ns_stack.into_iter().rev() {
        for (prefix, uri) in level {
            if uri.is_empty() {
                result.remove(&prefix);
            } else {
                result.insert(prefix, uri);
            }
        }
    }
    result
}

fn has_preceding_element(node: roxmltree::Node<'_, '_>) -> bool {
    let mut cur = node.prev_sibling();
    while let Some(n) = cur {
        if n.is_element() {
            return true;
        }
        cur = n.prev_sibling();
    }
    false
}

fn has_following_element(node: roxmltree::Node<'_, '_>) -> bool {
    let mut cur = node.next_sibling();
    while let Some(n) = cur {
        if n.is_element() {
            return true;
        }
        cur = n.next_sibling();
    }
    false
}

impl<'a> C14nContext<'a> {
    fn process_node(
        &self,
        node: roxmltree::Node<'_, '_>,
        output: &mut Vec<u8>,
        rendered_ns: &BTreeMap<String, String>,
    ) -> Result<(), C14nError> {
        match node.node_type() {
            roxmltree::NodeType::Root => {
                for child in node.children() {
                    self.process_node(child, output, rendered_ns)?;
                }
            }
            roxmltree::NodeType::Element => {
                self.process_element(node, output, rendered_ns)?;
            }
            roxmltree::NodeType::Text => {
                if let Some(text) = node.text() {
                    output.extend_from_slice(escape::escape_text(text).as_bytes());
                }
            }
            roxmltree::NodeType::Comment => {
                // Without-comments mode: skip
            }
            roxmltree::NodeType::PI => {
                if let Some(pi) = node.pi() {
                    let parent_is_root = node
                        .parent()
                        .map(|p| p.node_type() == roxmltree::NodeType::Root)
                        .unwrap_or(false);

                    if parent_is_root && has_preceding_element(node) {
                        output.extend_from_slice(b"\n");
                    }

                    output.extend_from_slice(b"<?");
                    output.extend_from_slice(pi.target.as_bytes());
                    if let Some(value) = pi.value {
                        output.extend_from_slice(b" ");
                        output.extend_from_slice(escape::escape_pi(value.trim_start()).as_bytes());
                    }
                    output.extend_from_slice(b"?>");

                    if parent_is_root && has_following_element(node) {
                        output.extend_from_slice(b"\n");
                    }
                }
            }
        }
        Ok(())
    }

    /// Namespace declarations to render at `node`, per the active C14N mode.
    ///
    /// Exclusive (`xml-exc-c14n#`): only namespaces *visibly utilized* by the element's own qualified name / attributes.
    /// Inclusive (`REC-xml-c14n-20010315`): every in-scope namespace, including those inherited from ancestors.
    ///
    /// Both emit a declaration only when it differs from what an output ancestor already rendered.
    fn namespace_decls(
        &self,
        node: roxmltree::Node<'_, '_>,
        inscope_ns: &BTreeMap<String, String>,
        rendered_ns: &BTreeMap<String, String>,
    ) -> Vec<NsDecl> {
        let mut ns_decls: Vec<NsDecl> = Vec::new();

        match self.mode {
            C14nMode::Exclusive => {
                let mut utilized: HashSet<String> = HashSet::new();
                utilized.insert(element_prefix(node));
                for attr in node.attributes() {
                    let pfx = attribute_prefix(node, &attr);
                    if !pfx.is_empty() {
                        utilized.insert(pfx);
                    }
                }
                for prefix in &utilized {
                    if prefix == "xml" {
                        continue;
                    }
                    if let Some(uri) = inscope_ns.get(prefix) {
                        if rendered_ns.get(prefix) != Some(uri) {
                            ns_decls.push(NsDecl {
                                prefix: prefix.clone(),
                                uri: uri.clone(),
                            });
                        }
                    } else if prefix.is_empty()
                        && rendered_ns.get("").map(|u| !u.is_empty()).unwrap_or(false)
                    {
                        ns_decls.push(NsDecl {
                            prefix: String::new(),
                            uri: String::new(),
                        });
                    }
                }
            }
            C14nMode::Inclusive => {
                for (prefix, uri) in inscope_ns {
                    if prefix == "xml" {
                        continue;
                    }
                    if rendered_ns.get(prefix) != Some(uri) {
                        ns_decls.push(NsDecl {
                            prefix: prefix.clone(),
                            uri: uri.clone(),
                        });
                    }
                }
                // The element undeclares the default namespace (`xmlns=""`) and an
                // output ancestor had rendered a non-empty one: emit the undeclaration.
                if !inscope_ns.contains_key("")
                    && rendered_ns.get("").map(|u| !u.is_empty()).unwrap_or(false)
                {
                    ns_decls.push(NsDecl {
                        prefix: String::new(),
                        uri: String::new(),
                    });
                }
            }
        }

        ns_decls.sort();
        ns_decls
    }

    fn process_element(
        &self,
        node: roxmltree::Node<'_, '_>,
        output: &mut Vec<u8>,
        rendered_ns: &BTreeMap<String, String>,
    ) -> Result<(), C14nError> {
        if let Some(ref skip) = self.skip
            && node.tag_name().namespace() == Some(skip.namespace)
            && node.tag_name().name() == skip.local_name
        {
            match skip.id {
                None => return Ok(()),
                Some(id) if node.attribute("Id") == Some(id) => return Ok(()),
                _ => {}
            }
        }

        let inscope_ns = collect_inscope_namespaces(node);
        let ns_decls = self.namespace_decls(node, &inscope_ns, rendered_ns);

        // Build Attr list
        let mut attrs: Vec<Attr> = Vec::new();
        for attr in node.attributes() {
            let pfx = attribute_prefix(node, &attr);
            let qname = if pfx.is_empty() {
                attr.name().to_owned()
            } else {
                format!("{pfx}:{}", attr.name())
            };
            attrs.push(Attr {
                ns_uri: attr.namespace().unwrap_or("").to_owned(),
                local_name: attr.name().to_owned(),
                qualified_name: qname,
                value: attr.value().to_owned(),
            });
        }
        attrs.sort();

        // Emit start tag
        let qname = qualified_element_name(node);
        output.extend_from_slice(b"<");
        output.extend_from_slice(qname.as_bytes());
        for ns in &ns_decls {
            output.extend_from_slice(ns.render().as_bytes());
        }
        for attr in &attrs {
            output.extend_from_slice(attr.render().as_bytes());
        }
        output.extend_from_slice(b">");

        // Build child rendered_ns: exclusive only propagates what it rendered,
        // inclusive propagates the full in-scope set (every namespace is rendered
        // by some ancestor, so children compare against the complete context).
        let mut child_rendered_ns = rendered_ns.clone();
        match self.mode {
            C14nMode::Exclusive => {
                for ns in &ns_decls {
                    child_rendered_ns.insert(ns.prefix.clone(), ns.uri.clone());
                }
            }
            C14nMode::Inclusive => {
                for (prefix, uri) in &inscope_ns {
                    if prefix != "xml" {
                        child_rendered_ns.insert(prefix.clone(), uri.clone());
                    }
                }
            }
        }

        // Recurse into children
        for child in node.children() {
            self.process_node(child, output, &child_rendered_ns)?;
        }

        // Emit end tag
        output.extend_from_slice(b"</");
        output.extend_from_slice(qname.as_bytes());
        output.extend_from_slice(b">");

        Ok(())
    }
}

pub(crate) fn canonicalize_doc(
    doc: &roxmltree::Document<'_>,
    mode: C14nMode,
    skip: Option<SkipElement<'_>>,
) -> Result<Vec<u8>, C14nError> {
    let mut output = Vec::new();
    let ctx = C14nContext { mode, skip };
    ctx.process_node(doc.root(), &mut output, &BTreeMap::new())?;
    Ok(output)
}

pub(crate) fn canonicalize_subtree(
    node: &roxmltree::Node<'_, '_>,
    mode: C14nMode,
    skip: Option<SkipElement<'_>>,
) -> Result<Vec<u8>, C14nError> {
    let mut output = Vec::new();
    let ctx = C14nContext { mode, skip };
    ctx.process_node(*node, &mut output, &BTreeMap::new())?;
    Ok(output)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use similar_asserts::assert_eq;
    use standardized_types::xades::XMLDSIG_NS;

    use super::super::{C14nMode, SkipElement, canonicalize, canonicalize_signature_subtree};

    fn c14n(xml: &str) -> String {
        String::from_utf8(
            canonicalize(xml, C14nMode::Exclusive, None).expect("canonicalize failed"),
        )
        .expect("invalid utf8")
    }

    fn inc(xml: &str) -> String {
        String::from_utf8(
            canonicalize(xml, C14nMode::Inclusive, None).expect("canonicalize failed"),
        )
        .expect("invalid utf8")
    }

    fn skip_signature(id: Option<&str>) -> Option<SkipElement<'_>> {
        Some(SkipElement {
            namespace: XMLDSIG_NS,
            local_name: "Signature",
            id,
        })
    }

    #[test]
    fn simple_document_no_decl() {
        let input = "<?xml version=\"1.0\"?>\n<doc>Hello</doc>";
        assert_eq!(c14n(input), "<doc>Hello</doc>");
    }

    #[test]
    fn pi_rendering() {
        let input = "<doc><?pi-with-data   some data  ?></doc>";
        assert_eq!(c14n(input), "<doc><?pi-with-data some data  ?></doc>");
    }

    #[test]
    fn w3c_3_2_whitespace() {
        // The input string includes both spaces and tabs
        let input = "<doc>\n   <clean>   </clean>\n   \t<dirty>\t   A\t   B\t   </dirty>\t\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";
        assert_eq!(c14n(input), input);
    }

    #[test]
    fn w3c_3_6_utf8() {
        let input = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<doc>\u{00A9}</doc>";
        assert_eq!(c14n(input), "<doc>\u{00A9}</doc>");
    }

    #[test]
    fn empty_element_expansion() {
        assert_eq!(c14n("<doc><empty/></doc>"), "<doc><empty></empty></doc>");
    }

    #[test]
    fn comments_stripped() {
        let input = "<a><!-- comment0 --><!-- comment1 --><!-- comment2 --></a>";
        assert_eq!(c14n(input), "<a></a>");
    }

    #[test]
    fn namespace_not_visibly_utilized() {
        let input = r#"<root xmlns:a="http://a" xmlns:b="http://b"><a:child/></root>"#;
        let result = c14n(input);
        assert!(result.contains("xmlns:a=\"http://a\""));
        assert!(!result.contains("xmlns:b"));
    }

    #[test]
    fn default_namespace_inherited() {
        let input = r#"<root xmlns="http://example.com"><child/></root>"#;
        assert_eq!(
            c14n(input),
            "<root xmlns=\"http://example.com\"><child></child></root>"
        );
    }

    #[test]
    fn default_namespace_undeclaration() {
        let input = r#"<root xmlns="http://example.com"><child xmlns=""/></root>"#;
        let result = c14n(input);
        assert!(result.contains("<child xmlns=\"\">"));
    }

    #[test]
    fn xml_prefix_never_declared() {
        let input = r#"<doc xml:lang="en"/>"#;
        let result = c14n(input);
        assert!(!result.contains("xmlns:xml"));
        assert!(result.contains("xml:lang=\"en\""));
    }

    #[test]
    fn attributes_sorted_canonically() {
        let input = r#"<doc z="1" a="2" m="3"/>"#;
        assert_eq!(c14n(input), r#"<doc a="2" m="3" z="1"></doc>"#);
    }

    #[test]
    fn multiple_namespace_prefixes() {
        let input = r#"<root xmlns="http://default" xmlns:a="http://a" xmlns:b="http://b"><a:foo/><b:bar/></root>"#;
        let result = c14n(input);
        assert!(result.contains("<a:foo xmlns:a=\"http://a\"></a:foo>"));
        assert!(result.contains("<b:bar xmlns:b=\"http://b\"></b:bar>"));
    }

    #[test]
    fn enveloped_removes_signature() {
        let xml = r#"<root xmlns="http://example.com"><data>hello</data><Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="sig1"><SignedInfo><CanonicalizationMethod/></SignedInfo><SignatureValue>abc</SignatureValue></Signature></root>"#;
        let result = String::from_utf8(
            canonicalize(xml, C14nMode::Exclusive, skip_signature(None)).expect("c14n failed"),
        )
        .expect("utf8");
        assert!(!result.contains("Signature"));
        assert!(!result.contains("SignatureValue"));
        assert!(result.contains("<data>hello</data>"));
    }

    #[test]
    fn enveloped_by_id_skips_matching_only() {
        let xml = r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature Id="keep"><ds:SignedInfo/></ds:Signature><ds:Signature Id="remove"><ds:SignedInfo/></ds:Signature></root>"#;
        let result = String::from_utf8(
            canonicalize(xml, C14nMode::Exclusive, skip_signature(Some("remove")))
                .expect("c14n failed"),
        )
        .expect("utf8");
        assert!(result.contains("Id=\"keep\""));
        assert!(!result.contains("Id=\"remove\""));
    }

    #[test]
    fn signed_info_extraction() {
        let xml = r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature Id="sig1"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:Reference URI=""/></ds:SignedInfo><ds:SignatureValue>abc</ds:SignatureValue></ds:Signature></root>"#;
        let result = String::from_utf8(
            canonicalize_signature_subtree(
                xml,
                C14nMode::Exclusive,
                Some("sig1"),
                XMLDSIG_NS,
                "SignedInfo",
            )
            .expect("c14n failed"),
        )
        .expect("utf8");
        assert!(result.contains("SignedInfo"));
        assert!(result.contains("CanonicalizationMethod"));
        assert!(!result.contains("SignatureValue"));
    }

    #[test]
    fn signed_info_inherits_namespace_from_ancestor() {
        let xml = r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature Id="s1"><ds:SignedInfo><ds:Reference URI=""/></ds:SignedInfo></ds:Signature></root>"#;
        let result = String::from_utf8(
            canonicalize_signature_subtree(
                xml,
                C14nMode::Exclusive,
                Some("s1"),
                XMLDSIG_NS,
                "SignedInfo",
            )
            .expect("c14n failed"),
        )
        .expect("utf8");
        assert!(
            result.starts_with("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""),
            "SignedInfo must declare xmlns:ds. Got: {result}"
        );
    }

    #[test]
    fn signed_info_not_found_errors() {
        let xml = r#"<root/>"#;
        let err = canonicalize_signature_subtree(
            xml,
            C14nMode::Exclusive,
            None,
            XMLDSIG_NS,
            "SignedInfo",
        );
        assert!(err.is_err());
    }

    #[test]
    fn cdata_normalized_to_text() {
        let input = "<doc><![CDATA[hello & world]]></doc>";
        assert_eq!(c14n(input), "<doc>hello &amp; world</doc>");
    }

    #[test]
    fn redundant_ns_across_siblings() {
        let input = r#"<root xmlns:a="http://a"><a:first/><a:second/></root>"#;
        let result = c14n(input);
        let count = result.matches("xmlns:a").count();
        assert_eq!(
            count, 2,
            "Each sibling should independently declare xmlns:a. Got: {result}"
        );
    }

    #[test]
    fn deeply_nested_prefix_from_root() {
        let input = r#"<r xmlns:p="http://p"><a><b><p:c/></b></a></r>"#;
        let result = c14n(input);
        assert!(result.contains("<p:c xmlns:p=\"http://p\"></p:c>"));
    }

    #[test]
    fn mixed_default_and_prefixed_ns() {
        let input =
            r#"<root xmlns="http://default" xmlns:x="http://x"><child><x:inner/></child></root>"#;
        let result = c14n(input);
        assert!(result.contains("<x:inner xmlns:x=\"http://x\"></x:inner>"));
    }

    #[test]
    fn idempotent() {
        let input = r#"<root xmlns:a="http://a" z="1" a="2"><a:child xml:lang="en"/></root>"#;
        let first = c14n(input);
        let second = c14n(&first);
        assert_eq!(first, second, "Canonicalization must be idempotent");
    }

    #[test]
    fn inclusive_renders_all_inscope_not_just_utilized() {
        // Exclusive drops the unused xmlns:b and redeclares xmlns:a on the child;
        // inclusive declares both at the root and the child inherits them.
        let input = r#"<root xmlns:a="http://a" xmlns:b="http://b"><a:child/></root>"#;
        assert_eq!(
            inc(input),
            r#"<root xmlns:a="http://a" xmlns:b="http://b"><a:child></a:child></root>"#
        );
    }

    #[test]
    fn inclusive_subtree_inherits_all_ancestor_namespaces() {
        let xml = r#"<root xmlns="http://d" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:x="http://x"><ds:Signature Id="s1"><ds:SignedInfo><ds:Reference URI=""/></ds:SignedInfo></ds:Signature></root>"#;
        let result = String::from_utf8(
            canonicalize_signature_subtree(
                xml,
                C14nMode::Inclusive,
                Some("s1"),
                XMLDSIG_NS,
                "SignedInfo",
            )
            .expect("c14n failed"),
        )
        .expect("utf8");
        // The apex must carry every in-scope namespace (default, ds, x), sorted
        // with the default first.
        assert!(
            result.starts_with(
                "<ds:SignedInfo xmlns=\"http://d\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:x=\"http://x\">"
            ),
            "inclusive SignedInfo must declare all inherited namespaces. Got: {result}"
        );
    }

    #[test]
    fn inclusive_does_not_redeclare_inherited_in_descendants() {
        let input = r#"<r xmlns:p="http://p"><a><p:c/></a></r>"#;
        // p is declared once at the root; descendants inherit it without
        // redeclaring (the defining difference from exclusive C14N).
        assert_eq!(
            inc(input),
            r#"<r xmlns:p="http://p"><a><p:c></p:c></a></r>"#
        );
    }
}
