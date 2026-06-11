use std::ops::{Add, Sub};
use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::Signer;
use one_crypto::signer::ecdsa::ECDSASigner;
use secrecy::SecretSlice;
use serde_json::json;
use shared_types::IdentifierId;
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use crate::config;
use crate::config::core_config::{CoreConfig, Fields, KeyAlgorithmType, Params};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::wallet_instance::{
    WalletInstance, WalletInstanceOs, WalletInstanceStatus, WalletProviderType,
};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::clock::DefaultClock;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTHeader, JWTPayload};
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::credential_formatter::common::SignatureProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::wallet_instance_repository::MockWalletInstanceRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::test_utilities::{dummy_organisation, generic_config, get_dummy_date};
use crate::service::wallet_provider::WalletProviderService;
use crate::service::wallet_provider::dto::{
    RegisterWalletUnitRequestDTO, WalletUnitFilterParamsDTO,
};

const BASE_URL: &str = "https://localhost";

fn mock_wallet_provider_service() -> WalletProviderService {
    WalletProviderService {
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        wallet_instance_repository: Arc::new(MockWalletInstanceRepository::default()),
        identifier_repository: Arc::new(MockIdentifierRepository::default()),
        history_repository: Arc::new(MockHistoryRepository::default()),
        trust_collection_repository: Arc::new(MockTrustCollectionRepository::default()),
        tx_manager: Arc::new(NoTransactionManager),
        key_provider: Arc::new(MockKeyProvider::default()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        revocation_method_provider: Arc::new(MockRevocationMethodProvider::default()),
        certificate_validator: Arc::new(MockCertificateValidator::default()),
        http_client: Arc::new(MockHttpClient::default()),
        clock: Arc::new(DefaultClock),
        base_url: Some(BASE_URL.to_string()),
        config: Arc::new(CoreConfig::default()),
        session_provider: Arc::new(NoSessionProvider),
    }
}

fn wallet_provider_config(
    integrity_check_enabled: bool,
) -> Fields<config::core_config::WalletProviderType> {
    Fields {
        r#type: config::core_config::WalletProviderType::ProcivisOne,
        display: "display".into(),
        order: None,
        priority: None,
        enabled: true,
        capabilities: None,
        params: Some(Params {
            public: Some(json!({
                "walletName": "Procivis One Dev Wallet",
                "walletClientId": "mock-client-id",
                "walletLink": "https://procivis.ch",
                "walletRegistration": "MANDATORY",
                "walletInstanceAttestation": {
                    "expirationTime": 60,
                    "integrityCheck": {
                        "enabled": integrity_check_enabled,
                        "android": {
                            "bundleId": "com.procivis...",
                            "signingCertificateFingerprints": ["test"],
                            "trustedAttestationCAs": ["-----BEGIN CERTIFICATE-----..."]
                        },
                        "ios": {
                            "bundleId": "com.procivis...",
                            "trustedAttestationCAs": ["-----BEGIN CERTIFICATE-----..."],
                            "enforceProductionBuild": true
                        }
                    },
                },
                "walletUnitAttestation": {
                    "expirationTime": 60
                },
                "deviceAuthLeeway": 60,
                "appVersion": {
                    "minimum": "v1.50.0",
                },
                "featureFlags": {
                    "trustEcosystemsEnabled": true,
                    "refreshCredentialBatchEnabled": true
                }
            })),
            private: None,
        }),
    }
}

#[tokio::test]
async fn test_register_wallet_unit() {
    // given
    let mut config = CoreConfig::default();
    let issuer_identifier_id: IdentifierId = Uuid::new_v4().into();

    let procivis_one_provider = "PROCIVIS_ONE";
    config.wallet_provider.insert(
        procivis_one_provider.to_string(),
        wallet_provider_config(false),
    );

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_wallet_provider()
        .returning(move |_| {
            Ok(Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deactivated_at: None,
                wallet_provider: Some(procivis_one_provider.to_string()),
                wallet_provider_issuer: Some(issuer_identifier_id),
                parent_organisation: None,
            }))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .return_once(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));

    let mut wallet_unit_repository = MockWalletInstanceRepository::new();
    wallet_unit_repository
        .expect_create_wallet_instance()
        .return_once(|wu| Ok(wu.id));

    let (issuer_private, issuer_public) = ECDSASigner::generate_key_pair();
    let issuer_public_clone = issuer_public.clone();
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .return_once(move |id, _| {
            Ok(Some(Identifier {
                id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "test".to_string(),
                r#type: IdentifierType::Key,
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: None,
                did: None,
                key: Some(Key {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    public_key: issuer_public_clone,
                    name: "".to_string(),
                    key_reference: None,
                    storage_type: "TEST".to_string(),
                    key_type: "ECDSA".to_string(),
                    organisation: dummy_organisation(None).into(),
                }),
                certificates: None,
                trust_information: None,
            }))
        });

    let issuer_key_handle = Ecdsa
        .reconstruct_key(&issuer_public, Some(issuer_private.clone()), None)
        .unwrap();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .returning(move |_| Ok(issuer_key_handle.clone()));

    let key_storage = Arc::new(key_storage);
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Ok(key_storage.clone()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let ssi_wallet_provider_service = WalletProviderService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        wallet_instance_repository: Arc::new(wallet_unit_repository),
        identifier_repository: Arc::new(identifier_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        config: Arc::new(config),
        ..mock_wallet_provider_service()
    };

    let (proof, holder_jwk) = create_proof().await;
    let request = RegisterWalletUnitRequestDTO {
        wallet_provider: procivis_one_provider.to_string(),
        os: WalletInstanceOs::Android,
        public_key: Some(holder_jwk.public_key_as_jwk().unwrap()),
        proof: Some(proof),
    };

    // when
    let result = ssi_wallet_provider_service
        .register_wallet_unit(request)
        .await
        .unwrap();

    // then
    assert!(result.nonce.is_none());
}

#[tokio::test]
async fn test_register_wallet_unit_integrity_check() {
    // given
    let mut config = CoreConfig::default();
    let issuer_identifier_id: IdentifierId = Uuid::new_v4().into();
    let procivis_one_provider = "PROCIVIS_ONE";
    config.wallet_provider.insert(
        procivis_one_provider.to_string(),
        wallet_provider_config(true),
    );

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_wallet_provider()
        .returning(move |_| {
            Ok(Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deactivated_at: None,
                wallet_provider: Some(procivis_one_provider.to_string()),
                wallet_provider_issuer: Some(issuer_identifier_id),
                parent_organisation: None,
            }))
        });

    let mut wallet_unit_repository = MockWalletInstanceRepository::new();
    wallet_unit_repository
        .expect_create_wallet_instance()
        .return_once(|wu| Ok(wu.id));

    let (issuer_private, issuer_public) = ECDSASigner::generate_key_pair();
    let issuer_public_clone = issuer_public.clone();
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .return_once(move |id, _| {
            Ok(Some(Identifier {
                id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "test".to_string(),
                r#type: IdentifierType::Key,
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: None,
                did: None,
                key: Some(Key {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    public_key: issuer_public_clone,
                    name: "".to_string(),
                    key_reference: None,
                    storage_type: "TEST".to_string(),
                    key_type: "ECDSA".to_string(),
                    organisation: dummy_organisation(None).into(),
                }),
                certificates: None,
                trust_information: None,
            }))
        });

    let issuer_key_handle = Ecdsa
        .reconstruct_key(&issuer_public, Some(issuer_private.clone()), None)
        .unwrap();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .return_once(|_| Ok(issuer_key_handle));

    let key_storage = Arc::new(key_storage);
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Ok(key_storage.clone()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let ssi_wallet_provider_service = WalletProviderService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        wallet_instance_repository: Arc::new(wallet_unit_repository),
        identifier_repository: Arc::new(identifier_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        config: Arc::new(config),
        ..mock_wallet_provider_service()
    };

    let request = RegisterWalletUnitRequestDTO {
        wallet_provider: "PROCIVIS_ONE".to_string(),
        os: WalletInstanceOs::Android,
        public_key: None,
        proof: None,
    };

    // when
    let result = ssi_wallet_provider_service
        .register_wallet_unit(request)
        .await
        .unwrap();

    // then
    assert!(result.nonce.is_some());
}

#[tokio::test]
async fn provider_wallet_unit_ops_session_org_mismatch() {
    // given
    let service = WalletProviderService {
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        config: Arc::new(generic_config().core),
        ..mock_wallet_provider_service()
    };

    // when
    let result = service
        .get_wallet_unit_list(ListQueryDTO {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            filter: WalletUnitFilterParamsDTO {
                name: None,
                ids: None,
                status: None,
                os: None,
                wallet_provider_type: None,
                attestation: None,
                organisation_id: Uuid::new_v4().into(),
                created_date_after: None,
                created_date_before: None,
                user_sub: None,
            },
            include: None,
        })
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn provider_get_wallet_unit_session_org_mismatch() {
    let wallet_unit = WalletInstance {
        id: Uuid::new_v4().into(),
        name: "".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        os: WalletInstanceOs::Ios,
        status: WalletInstanceStatus::Active,
        wallet_provider_type: WalletProviderType::ProcivisOne,
        wallet_provider_name: "test provider".to_string(),
        authentication_key_jwk: None,
        last_issuance: None,
        nonce: None,
        user_nonce: None,
        user_sub: None,
        organisation: Some(dummy_organisation(None)),
        attested_keys: None,
    };
    let mut wallet_unit_repository = MockWalletInstanceRepository::new();
    wallet_unit_repository
        .expect_get_wallet_instance()
        .returning(move |_, _| Ok(Some(wallet_unit.clone())));

    // given
    let service = WalletProviderService {
        wallet_instance_repository: Arc::new(wallet_unit_repository),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        config: Arc::new(generic_config().core),
        ..mock_wallet_provider_service()
    };

    // when
    let result = service.get_wallet_unit(&Uuid::new_v4().into()).await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

async fn create_proof() -> (String, KeyHandle) {
    let (holder_private, holder_public) = ECDSASigner::generate_key_pair();
    let holder_key_handle = Ecdsa
        .reconstruct_key(&holder_public, Some(holder_private.clone()), None)
        .unwrap();

    let jwk = holder_key_handle.public_key_as_jwk().unwrap();

    let now = crate::clock::now_utc();
    let proof = Jwt {
        header: JWTHeader {
            algorithm: "ES256".to_string(),
            key_id: None,
            r#type: None,
            jwk: Some(jwk.clone()),
            jwt: None,
            key_attestation: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: Some(now.sub(Duration::minutes(30))),
            expires_at: Some(now.add(Duration::minutes(30))),
            invalid_before: Some(now.sub(Duration::minutes(20))),
            issuer: None,
            subject: None,
            audience: Some(vec![BASE_URL.to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    };

    let signer = FakeEcdsaSigner {
        public_key: holder_public,
        private_key: holder_private,
        key_id: "".to_string(),
    };
    let proof = proof.tokenize(Some(&signer)).await.unwrap();

    (proof, holder_key_handle)
}

struct FakeEcdsaSigner {
    public_key: Vec<u8>,
    private_key: SecretSlice<u8>,
    key_id: String,
}

#[async_trait]
impl SignatureProvider for FakeEcdsaSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(ECDSASigner.sign(message, &self.public_key, &self.private_key)?)
    }

    fn get_key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        Ok(KeyAlgorithmType::Ecdsa)
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok("ES256".to_string())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

// ===== validate_user_id_token tests =====

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct TestIdTokenClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

fn user_auth_params(required: bool) -> super::dto::UserAuthenticationParams {
    super::dto::UserAuthenticationParams {
        required,
        identity_provider: "https://idp.example.com".to_string(),
        client_id: "my-client".to_string(),
        redirect_uri: "myapp://callback".to_string(),
        token_validation: super::dto::TokenValidationParams {
            aud: "test-aud".to_string(),
            iss: "https://idp.example.com".to_string(),
            jwks_uri: "https://idp.example.com/.well-known/jwks.json".to_string(),
        },
    }
}

async fn make_user_id_token(
    iss: &str,
    aud: &str,
    sub: Option<&str>,
    nonce: Option<&str>,
) -> (String, standardized_types::jwk::PublicJwk) {
    let (private, public) = ECDSASigner::generate_key_pair();
    let key_handle = Ecdsa
        .reconstruct_key(&public, Some(private.clone()), None)
        .unwrap();
    let public_jwk = key_handle.public_key_as_jwk().unwrap();

    let jwt: Jwt<TestIdTokenClaims> = Jwt {
        header: JWTHeader {
            algorithm: "ES256".to_string(),
            key_id: None,
            r#type: None,
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: Some(iss.to_string()),
            subject: sub.map(str::to_string),
            audience: Some(vec![aud.to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: TestIdTokenClaims {
                nonce: nonce.map(str::to_string),
            },
        },
    };

    let signer = FakeEcdsaSigner {
        public_key: public,
        private_key: private,
        key_id: "".to_string(),
    };
    let token = jwt.tokenize(Some(&signer)).await.unwrap();
    (token, public_jwk)
}

fn make_jwks_http_client(public_jwk: standardized_types::jwk::PublicJwk) -> MockHttpClient {
    let jwks_body = serde_json::to_vec(&serde_json::json!({ "keys": [public_jwk] })).unwrap();
    let mut http_client = MockHttpClient::new();
    http_client.expect_get().returning(move |url| {
        let body = jwks_body.clone();
        let url_owned = url.to_string();
        let url_for_inner = url_owned.clone();
        let mut inner = MockHttpClient::new();
        inner.expect_send().returning(move |_, _, _, _, _| {
            Ok(Response {
                body: body.clone(),
                headers: Default::default(),
                status: StatusCode(200),
                request: Request {
                    body: None,
                    headers: Default::default(),
                    method: Method::Get,
                    url: url_for_inner.clone(),
                    timeout: None,
                },
            })
        });
        RequestBuilder::new(Arc::new(inner), Method::Get, &url_owned)
    });
    http_client
}

fn make_jwks_http_client_error() -> MockHttpClient {
    let mut http_client = MockHttpClient::new();
    http_client.expect_get().returning(|url| {
        let url_owned = url.to_string();
        let url_for_inner = url_owned.clone();
        let mut inner = MockHttpClient::new();
        inner.expect_send().returning(move |_, _, _, _, _| {
            Ok(Response {
                body: vec![],
                headers: Default::default(),
                status: StatusCode(500),
                request: Request {
                    body: None,
                    headers: Default::default(),
                    method: Method::Get,
                    url: url_for_inner.clone(),
                    timeout: None,
                },
            })
        });
        RequestBuilder::new(Arc::new(inner), Method::Get, &url_owned)
    });
    http_client
}

fn make_key_algorithm_provider() -> MockKeyAlgorithmProvider {
    let mut kap = MockKeyAlgorithmProvider::new();
    kap.expect_key_algorithm_from_jose_alg()
        .returning(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));
    kap
}

#[tokio::test]
async fn validate_user_id_token_no_token_not_required() {
    let service = mock_wallet_provider_service();
    let result = service.validate_user_id_token(None, None, None).await;
    assert_eq!(result.unwrap(), None);
}

#[tokio::test]
async fn validate_user_id_token_no_token_optional_auth() {
    let service = mock_wallet_provider_service();
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(None, Some(&auth), None)
        .await;
    assert_eq!(result.unwrap(), None);
}

#[tokio::test]
async fn validate_user_id_token_no_token_required() {
    let service = mock_wallet_provider_service();
    let auth = user_auth_params(true);
    let result = service
        .validate_user_id_token(None, Some(&auth), None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0447);
}

#[tokio::test]
async fn validate_user_id_token_not_expected() {
    let service = mock_wallet_provider_service();
    let result = service
        .validate_user_id_token(Some("some.jwt.token"), None, None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0446);
}

#[tokio::test]
async fn validate_user_id_token_invalid_jwt_format() {
    let service = mock_wallet_provider_service();
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some("not-a-jwt"), Some(&auth), Some("nonce"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_jwks_fetch_error() {
    let (token, _) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let service = WalletProviderService {
        http_client: Arc::new(make_jwks_http_client_error()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0347);
}

#[tokio::test]
async fn validate_user_id_token_no_matching_jwks_key() {
    let (token, _) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let jwks_body = serde_json::to_vec(&serde_json::json!({ "keys": [] })).unwrap();
    let mut http_client = MockHttpClient::new();
    http_client.expect_get().returning(move |url| {
        let body = jwks_body.clone();
        let url_owned = url.to_string();
        let url_for_inner = url_owned.clone();
        let mut inner = MockHttpClient::new();
        inner.expect_send().returning(move |_, _, _, _, _| {
            Ok(Response {
                body: body.clone(),
                headers: Default::default(),
                status: StatusCode(200),
                request: Request {
                    body: None,
                    headers: Default::default(),
                    method: Method::Get,
                    url: url_for_inner.clone(),
                    timeout: None,
                },
            })
        });
        RequestBuilder::new(Arc::new(inner), Method::Get, &url_owned)
    });

    let service = WalletProviderService {
        http_client: Arc::new(http_client),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_invalid_iss() {
    let (token, public_jwk) = make_user_id_token(
        "https://wrong-idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let service = WalletProviderService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_invalid_aud() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "wrong-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let service = WalletProviderService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_missing_user_nonce() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let service = WalletProviderService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_nonce_mismatch() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("wrong-nonce"),
    )
    .await;

    let service = WalletProviderService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("expected-nonce"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_missing_sub() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        None, // no sub
        Some("nonce-123"),
    )
    .await;

    let service = WalletProviderService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_success() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub-123"),
        Some("nonce-123"),
    )
    .await;

    let service = WalletProviderService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap(), Some("user-sub-123".to_string()));
}
