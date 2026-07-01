use std::sync::Arc;

use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::service::certificate::CertificateService;
use crate::service::certificate::error::CertificateServiceError;
use crate::service::test_utilities::{dummy_identifier, dummy_organisation, get_dummy_date};

#[tokio::test]
async fn test_get_cert_fail_session_org_mismatch() {
    let mut cert_repo = MockCertificateRepository::new();
    cert_repo.expect_get().returning(|_| {
        Ok(Some(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id: Uuid::new_v4().into(),
            organisation: dummy_organisation(None).into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            expiry_date: get_dummy_date(),
            name: "".to_string(),
            chain: "".to_string(),
            fingerprint: "".to_string(),
            state: CertificateState::NotYetActive,
            roles: vec![],
            key: None,
        }))
    });
    let service = CertificateService {
        certificate_repository: Arc::new(cert_repo),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service.get_certificate(Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_get_certificate_authority_invalid_identifier() {
    let id = Uuid::new_v4().into();

    let mut certificate_repository = MockCertificateRepository::new();
    certificate_repository.expect_get().returning(|id| {
        Ok(Some(Certificate {
            id,
            identifier_id: Uuid::new_v4().into(),
            organisation: dummy_organisation(None).into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            expiry_date: get_dummy_date(),
            deleted_at: None,
            name: "".to_string(),
            chain: "".to_string(),
            fingerprint: "".to_string(),
            state: CertificateState::Active,
            roles: vec![],
            key: None,
        }))
    });

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().returning(|_, _| {
        Ok(Some(Identifier {
            r#type: IdentifierType::Certificate,
            ..dummy_identifier()
        }))
    });

    let service = CertificateService {
        certificate_repository: Arc::new(certificate_repository),
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service.get_certificate_authority(id).await;
    assert!(matches!(result, Err(CertificateServiceError::NotFound(_))));
}

const TEST_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBODCB66ADAgECAhQjDWW20goQ5ZYZHnUYjgEAtpYAxjAFBgMrZXAwEjEQMA4G
A1UEAwwHQ0EgY2VydDAeFw0yMzA3MjgxMzA5MDhaFw0zNTAxMjYxMzA5MDhaMBIx
EDAOBgNVBAMMB0NBIGNlcnQwKjAFBgMrZXADIQBKBEnJk+6LyU8tcMSYIw8mvo06
E2W4JVTSZRP1JavvX6NTMFEwHwYDVR0jBBgwFoAUYSDrfq7B9LW8JqFf8Goypix1
9fswHQYDVR0OBBYEFGEg636uwfS1vCahX/BqMqYsdfX7MA8GA1UdEwEB/wQFMAMB
Af8wBQYDK2VwA0EAia2OnNqDv08Y8X6r1e7iBsgYsEa6V2Df65WDMKd/8LHCuhvL
GsPNAYTwQu1egNMnoBk0k0cwNJCBJmS3zEGaDw==
-----END CERTIFICATE-----";

#[tokio::test]
async fn test_get_certificate_pem_success() {
    let id = Uuid::new_v4().into();

    let mut certificate_repository = MockCertificateRepository::new();
    certificate_repository.expect_get().returning(|id| {
        Ok(Some(Certificate {
            id,
            identifier_id: Uuid::new_v4().into(),
            organisation: dummy_organisation(None).into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            expiry_date: get_dummy_date(),
            deleted_at: None,
            name: "".to_string(),
            chain: TEST_CERTIFICATE_PEM.to_string(),
            fingerprint: "".to_string(),
            state: CertificateState::Active,
            roles: vec![],
            key: None,
        }))
    });

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().returning(|_, _| {
        Ok(Some(Identifier {
            r#type: IdentifierType::Certificate,
            ..dummy_identifier()
        }))
    });

    let service = CertificateService {
        certificate_repository: Arc::new(certificate_repository),
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service.get_certificate_pem(id).await.unwrap();
    assert_eq!(result, TEST_CERTIFICATE_PEM);
}

#[tokio::test]
async fn test_get_certificate_pem_invalid_identifier() {
    let id = Uuid::new_v4().into();

    let mut certificate_repository = MockCertificateRepository::new();
    certificate_repository.expect_get().returning(|id| {
        Ok(Some(Certificate {
            id,
            identifier_id: Uuid::new_v4().into(),
            organisation: dummy_organisation(None).into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            expiry_date: get_dummy_date(),
            deleted_at: None,
            name: "".to_string(),
            chain: TEST_CERTIFICATE_PEM.to_string(),
            fingerprint: "".to_string(),
            state: CertificateState::Active,
            roles: vec![],
            key: None,
        }))
    });

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().returning(|_, _| {
        Ok(Some(Identifier {
            r#type: IdentifierType::CertificateAuthority,
            ..dummy_identifier()
        }))
    });

    let service = CertificateService {
        certificate_repository: Arc::new(certificate_repository),
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service.get_certificate_pem(id).await;
    assert!(matches!(result, Err(CertificateServiceError::NotFound(_))));
}
