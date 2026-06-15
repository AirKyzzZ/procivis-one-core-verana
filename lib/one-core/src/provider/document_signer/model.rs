use serde::Serialize;
pub use standardized_types::csc::{ConformanceLevel, HashAlgorithm, SignatureQualifier};
use standardized_types::csc::{SignatureAlgorithm, SignatureFormat};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentSignerCapabilities {
    pub signature_qualifiers: Vec<SignatureQualifier>,
    pub signature_formats: Vec<SignatureFormat>,
    pub conformance_levels: Vec<ConformanceLevel>,
    pub hash_algorithms: Vec<HashAlgorithm>,
    pub signature_algorithms: Vec<SignatureAlgorithm>,
}

#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    pub document: Vec<u8>,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Authorization {
    pub authorization_url: String,
    pub code_verifier: String,
}

/// `redirect_uri` and `document` must match the values used to build the authorization URL.
#[derive(Clone, Debug)]
pub struct SignRequest {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: Option<String>,
    pub document: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SignedDocument {
    pub content: Vec<u8>,
}
