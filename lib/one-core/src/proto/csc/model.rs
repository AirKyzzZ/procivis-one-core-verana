use standardized_types::csc::{
    ConformanceLevel, HashAlgorithm, SignatureAlgorithm, SignatureFormat, SignatureQualifier,
};

pub struct AuthorizationUrlRequest<'a> {
    pub oauth_url: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub account_token: &'a str,
    pub signature_qualifier: SignatureQualifier,
    pub hash: &'a [u8],
    pub hash_algorithm: HashAlgorithm,
}

#[derive(Debug)]
pub struct Authorization {
    pub authorization_url: String,
    pub code_verifier: String,
}

pub struct TokenRequest<'a> {
    pub oauth_url: &'a str,
    pub code: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
}

#[derive(Debug)]
pub struct CredentialToken {
    pub access_token: String,
    pub credential_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct CredentialInfo {
    pub key_algorithms: Vec<String>,
    pub certificate: Option<CertificateInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct CertificateInfo {
    pub x5c: Vec<String>,
}

impl CredentialInfo {
    pub fn signing_algorithm(&self, preferred_hash: HashAlgorithm) -> Option<SignatureAlgorithm> {
        let supported: Vec<SignatureAlgorithm> = self
            .key_algorithms
            .iter()
            .filter_map(|oid| SignatureAlgorithm::from_oid(oid))
            .collect();

        supported
            .iter()
            .copied()
            .find(|alg| alg.digest() == Some(preferred_hash))
            .or_else(|| supported.iter().copied().find(|alg| alg.digest().is_none()))
            .or_else(|| supported.first().copied())
    }
}

pub struct SignDocumentRequest<'a> {
    pub api_url: &'a str,
    pub access_token: &'a str,
    pub credential_id: &'a str,
    pub document: &'a [u8],
    pub sign_algo: &'a str,
    pub signature_format: SignatureFormat,
    pub conformance_level: ConformanceLevel,
}

pub struct SignHashRequest<'a> {
    pub api_url: &'a str,
    pub access_token: &'a str,
    pub credential_id: &'a str,
    pub hashes: &'a [&'a [u8]],
    pub sign_algo: SignatureAlgorithm,
    pub hash_algo: HashAlgorithm,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use standardized_types::csc::{HashAlgorithm, SignatureAlgorithm};

    use super::CredentialInfo;

    fn info_with_algos(algos: &[&str]) -> CredentialInfo {
        CredentialInfo {
            key_algorithms: algos.iter().map(|s| s.to_string()).collect(),
            certificate: None,
        }
    }

    #[test]
    fn signing_algorithm_prefers_digest_matching_the_configured_hash() {
        let chosen =
            info_with_algos(&["1.2.840.10045.4.3.2"]).signing_algorithm(HashAlgorithm::Sha256);
        assert_eq!(chosen, Some(SignatureAlgorithm::EcdsaSha256));
    }

    #[test]
    fn signing_algorithm_picks_the_ecdsa_variant_matching_the_hash() {
        let chosen = info_with_algos(&["1.2.840.10045.4.3.2", "1.2.840.10045.4.3.4"])
            .signing_algorithm(HashAlgorithm::Sha512);
        assert_eq!(chosen, Some(SignatureAlgorithm::EcdsaSha512));
    }

    #[test]
    fn signing_algorithm_falls_back_to_rsa_when_no_digest_matches() {
        let chosen =
            info_with_algos(&["1.2.840.113549.1.1.1"]).signing_algorithm(HashAlgorithm::Sha256);
        assert_eq!(chosen, Some(SignatureAlgorithm::Rsa));
    }

    #[test]
    fn signing_algorithm_ignores_unmodeled_oids() {
        let chosen = info_with_algos(&["1.3.6.1.4.1.99999", "1.2.840.10045.4.3.3"])
            .signing_algorithm(HashAlgorithm::Sha384);
        assert_eq!(chosen, Some(SignatureAlgorithm::EcdsaSha384));
    }

    #[test]
    fn signing_algorithm_returns_none_when_nothing_recognized() {
        let chosen =
            info_with_algos(&["1.3.6.1.4.1.99999"]).signing_algorithm(HashAlgorithm::Sha256);
        assert_eq!(chosen, None);
    }
}
