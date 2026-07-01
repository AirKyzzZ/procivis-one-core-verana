use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use assert2::let_assert;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use dcql::MsoMdocMeta;
use indexmap::IndexMap;
use mockall::predicate::{always, eq};
use one_crypto::encryption::encrypt_data;
use secrecy::SecretSlice;
use serde_json::{Value, json};
use shared_types::CredentialFormat;
use similar_asserts::assert_eq;
use standardized_types::etsi_119_472::disclosure_policy::{DisclosurePolicy, PolicyType};
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use time::Duration;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::OpenID4VCIFinal1_0;
use super::model::{
    HolderInteractionData, OpenID4VCICredentialRequestDTO, OpenID4VCICredentialRequestIdentifier,
    OpenID4VCICredentialRequestProofs, OpenID4VCIGrants, OpenID4VCIPreAuthorizedCodeGrant,
};
use super::service::create_credential_offer;
use crate::config::core_config::{
    CoreConfig, Fields, FormatType, KeyAlgorithmType, KeySecurityLevelType,
};
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity, LayoutType};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::history::{HistoryAction, TrustResolutionResult};
use crate::model::holder_wallet_instance::HolderWalletInstance;
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::localized_text::{LocalizedTextEntityType, LocalizedTextField};
use crate::model::wallet_instance::{WalletInstanceStatus, WalletProviderType};
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::credential_schema::importer::MockCredentialSchemaImporter;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::http_client::{MockHttpClient, Request, RequestBuilder, Response, StatusCode};
use crate::proto::identifier_creator::{
    CreateLocalIdentifierRequest, IdentifierName, IdentifierRole, MockIdentifierCreator,
    RemoteIdentifierRelation,
};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::wallet_instance::{IssuedWalletUnitAttestations, MockHolderWalletUnitProto};
use crate::proto::wrp_validator::MockWRPValidator;
use crate::proto::wrp_validator::model::{
    AccessCertificateResult, RegistrationCertificateResult, TrustMode,
};
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::MockOpenIDMetadataFetcher;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{IdentifierDetails, MockSignatureProvider};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::did_method::{DidCreated, MockDidMethod};
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::model::{
    InvitationResponseEnum, KeyStorageSecurityLevel, OpenID4VCIKeyAttestationsRequired,
    OpenID4VCIProofTypeSupported,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialMetadataClaimResponseDTO, OpenID4VCICredentialMetadataResponseDTO,
    OpenID4VCIIssuerMetadataClaimDisplay, OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
};
use crate::provider::issuance_protocol::{HolderBindingInput, IssuanceProtocol};
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePrivateKeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::model::GeneratedKey;
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use crate::provider::key_security_level::MockKeySecurityLevel;
use crate::provider::key_security_level::dto::KeySecurityLevelCapabilities;
use crate::provider::key_security_level::provider::MockKeySecurityLevelProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::{KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::signer::registration_certificate;
use crate::provider::signer::registration_certificate::model::{Status, SupervisoryAuthority};
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::holder_wallet_instance_repository::MockHolderWalletInstanceRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, get_dummy_date,
};
use crate::service::wallet_provider::dto::IssueWalletUnitAttestationResponseDTO;

#[derive(Default)]
struct TestInputs {
    pub credential_repository: MockCredentialRepository,
    pub key_repository: MockKeyRepository,
    pub identifier_creator: MockIdentifierCreator,
    pub metadata_cache: MockOpenIDMetadataFetcher,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub credential_schema_importer: Option<MockCredentialSchemaImporter>,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_provider: MockRevocationMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub key_security_level_provider: MockKeySecurityLevelProvider,
    pub certificate_validator: MockCertificateValidator,
    pub holder_wallet_unit_proto: MockHolderWalletUnitProto,
    pub holder_wallet_unit_repository: MockHolderWalletInstanceRepository,
    pub wrp_validator: MockWRPValidator,
    pub history_repository: MockHistoryRepository,
    pub interaction_repository: MockInteractionRepository,
    pub config: CoreConfig,
    pub params: Option<serde_json::Value>,
    pub client: Option<MockHttpClient>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VCIFinal1_0 {
    OpenID4VCIFinal1_0::new(
        inputs
            .client
            .map(|mock| Arc::new(mock) as _)
            .unwrap_or(Arc::new(ReqwestClient::default())),
        Arc::new(inputs.metadata_cache),
        Arc::new(inputs.credential_repository),
        Arc::new(inputs.key_repository),
        Arc::new(inputs.identifier_creator),
        inputs
            .credential_schema_importer
            .map(|m| Arc::new(m) as _)
            .unwrap_or_else(|| Arc::new(MockCredentialSchemaImporter::new())),
        Arc::new(inputs.credential_schema_repository),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.revocation_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.key_security_level_provider),
        Arc::new(inputs.blob_storage_provider),
        Some("http://base_url".to_string()),
        Arc::new(inputs.config),
        inputs.params.unwrap_or({
            let mut params = test_params("openid-credential-offer");
            params["credentialOfferByValue"] = json!(false);
            params
        }),
        "OPENID4VCI_FINAL1".to_string(),
        Arc::new(inputs.holder_wallet_unit_proto),
        Arc::new(inputs.holder_wallet_unit_repository),
        Arc::new(inputs.certificate_validator),
        Arc::new(inputs.wrp_validator),
        Arc::new(inputs.history_repository),
        Arc::new(NoSessionProvider),
        Arc::new(inputs.interaction_repository),
    )
    .unwrap()
}

fn generic_credential_did() -> Credential {
    let now = crate::clock::now_utc();
    let issuer_did = Did {
        deleted_at: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Remote,
        did_method: "KEY".into(),
        keys: Default::default(),
        deactivated: false,
        organisation: dummy_organisation(None).into(),
        log: None,
    };
    let issuer_identifier = Identifier {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        r#type: IdentifierType::Did,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
        did: Some(issuer_did),
        key: None,
        certificates: None,
        trust_information: None,
    };
    generic_credential(issuer_identifier)
}

fn generic_credential_did_with_holder_identifier() -> Credential {
    let now = crate::clock::now_utc();
    let mut credential = generic_credential_did();
    credential.holder_identifier = Some(Identifier {
        id: Uuid::from_str("a322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "holder identifier".to_string(),
        r#type: IdentifierType::Key,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
        did: None,
        key: Some(Key {
            key_type: "ECDSA".to_string(),
            ..dummy_key()
        }),
        certificates: None,
        trust_information: None,
    });
    credential
}

fn generic_credential_key() -> Credential {
    let now = crate::clock::now_utc();
    let issuer_key = Key {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        public_key: vec![
            3, 74, 21, 88, 157, 81, 251, 128, 145, 27, 187, 39, 111, 10, 236, 74, 221, 234, 194,
            44, 131, 73, 67, 110, 216, 155, 241, 212, 248, 141, 174, 74, 68,
        ],
        name: "key1".to_string(),
        key_reference: None,
        storage_type: "LOCAL".to_string(),
        organisation: dummy_organisation(None).into(),
        key_type: "ECDSA".to_string(),
    };
    let issuer_identifier = Identifier {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "key1".to_string(),
        r#type: IdentifierType::Key,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
        did: None,
        key: Some(issuer_key),
        certificates: None,
        trust_information: None,
    };
    let mut credential = generic_credential(issuer_identifier);
    let holder_identifier = Identifier {
        id: Uuid::from_str("a322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "holder identifier".to_string(),
        r#type: IdentifierType::Key,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
        did: None,
        key: Some(dummy_key()),
        certificates: None,
        trust_information: None,
    };
    credential.holder_identifier = Some(holder_identifier);
    credential
}

fn generic_credential(issuer_identifier: Identifier) -> Credential {
    let now = crate::clock::now_utc();

    let claim_schema = ClaimSchema {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };

    let credential_schema_format_id = Uuid::new_v4().into();
    let claim_schema_mapping = CredentialSchemaFormatClaimSchema {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        credential_schema_format_id,
        claim_schema_id: claim_schema.id,
        technical_key: "NUMBER".to_string(),
        namespace: None,
    };

    let credential_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();

    let credential_schema_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();
    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(vec![Claim {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some("123".to_string()),
            path: claim_schema.key.to_owned(),
            selectively_disclosable: false,
            schema: Some(claim_schema.clone()),
        }]),
        issuer_certificate: issuer_identifier
            .certificates
            .as_ref()
            .and_then(|certs| certs.first().cloned()),
        issuer_identifier: Some(issuer_identifier),
        holder_identifier: None,
        schema: Some(CredentialSchema {
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            key_storage_security: Some(KeyStorageSecurity::Basic),
            last_modified: now,
            name: "schema".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: credential_schema_format_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_id,
                format: "JWT".into(),
                schema_id: "CredentialSchemaId".to_owned(),
                claim_mappings: vec![claim_schema_mapping].into(),
            }]
            .into(),
            claim_schemas: vec![claim_schema].into(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            organisation: dummy_organisation(None).into(),
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        }),
        interaction: Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: now,
            data: Some(vec![1, 2, 3]),
            last_modified: now,
            organisation: None,
            nonce_id: None,
            interaction_type: InteractionType::Issuance,
            expires_at: None,
        }),
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,

        subscriber_information: None,
    }
}

fn dummy_config() -> CoreConfig {
    let mut config = CoreConfig::default();

    config.format.insert(
        "JWT".into(),
        Fields {
            r#type: FormatType::Jwt,
            display: "display".into(),
            order: None,
            priority: None,
            enabled: true,
            capabilities: None,
            params: None,
        },
    );

    config
}

#[tokio::test]
async fn test_generate_offer() {
    let protocol_base_url = "BASE_URL/ssi/openid4vci/final-1.0".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential_did();
    let issuer_identifier_id = credential.issuer_identifier.as_ref().unwrap().id;

    let offer = create_credential_offer(
        &protocol_base_url,
        &credential.protocol,
        &interaction_id.to_string(),
        credential.schema.as_ref().unwrap(),
        issuer_identifier_id,
    )
    .await
    .unwrap();

    assert_eq!(
        json!(&offer),
        json!({
            "credential_issuer": format!("BASE_URL/ssi/openid4vci/final-1.0/{}/{issuer_identifier_id}/c322aa7f-9803-410d-b891-939b279fb965", credential.protocol),
            "credential_configuration_ids" : [
                credential.schema.as_ref().unwrap().schema_id().await.unwrap(),
            ],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
            }
        })
    )
}

#[tokio::test]
async fn test_generate_share_credentials() {
    let credential = generic_credential_did();
    let protocol = setup_protocol(Default::default());

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    assert_eq!(
        result.url,
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Ffinal-1.0%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
}

#[tokio::test]
async fn test_generate_share_credentials_offer_by_value() {
    let credential = generic_credential_did();

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params("openid-credential-offer")),
        ..Default::default()
    });

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    // Everything except for interaction id is here.
    // Generating token with predictable interaction id is tested somewhere else.
    assert!(
        result.url.starts_with(r#"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Ffinal-1.0%2FOPENID4VCI_FINAL1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credential_configuration_ids%22%3A%5B%22CredentialSchemaId%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%"#)
    );
}

#[tokio::test]
async fn test_holder_accept_credential_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let key = dummy_key();
    let mut credential = generic_credential_did_with_holder_identifier();
    credential.holder_identifier.as_mut().unwrap().key = Some(key.clone());

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: credential
            .schema
            .as_ref()
            .unwrap()
            .schema_id()
            .await
            .unwrap(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{"credential": "credential"}],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_accepted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let identifier = dummy_identifier();
    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .return_once({
            let identifier = identifier.clone();
            move |_, _, _| Ok((identifier, RemoteIdentifierRelation::Key(dummy_key())))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(|history| {
            assert_eq!(history.action, HistoryAction::TrustResolved);
            true
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config: dummy_config(),
        ..Default::default()
    });
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );

    assert!(issuer_response.batch_items.is_empty());

    let single_credential = issuer_response.main_credential.credential;
    assert_eq!(single_credential.id, credential.id);
    assert_eq!(
        single_credential.issuer_identifier.as_ref().unwrap().id,
        identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_credential_none_existing_issuer_key_id_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let credential = generic_credential_key();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: credential
            .schema
            .as_ref()
            .unwrap()
            .schema_id()
            .await
            .unwrap(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{"credential": "credential"}],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });
    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider.expect_parse_jwk().returning(|k| {
        let key = Ecdsa.parse_jwk(k).unwrap();
        Ok(ParsedKey {
            key,
            algorithm_type: KeyAlgorithmType::Ecdsa,
        })
    });

    let jwk = PublicJwk::Ec(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
        y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
    });
    key_algorithm_provider.expect_reconstruct_key().returning({
        let jwk = jwk.clone();
        move |_, _, _, _| {
            let jwk = jwk.clone();
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| Ok(jwk));

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        }
    });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            eq(IdentifierDetails::Key(jwk)),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .returning(|_, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(|history| {
            assert_eq!(history.action, HistoryAction::TrustResolved);
            true
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let key = Key {
        id: Uuid::new_v4().into(),
        ..dummy_key()
    };
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Did,
                    did: Some(Did {
                        keys: vec![RelatedKey {
                            role: KeyRole::Authentication,
                            key: key.to_owned(),
                            reference: "ref".to_string(),
                        }]
                        .into(),
                        ..dummy_did()
                    }),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );
    assert!(issuer_response.batch_items.is_empty());

    let single_credential = issuer_response.main_credential.credential;
    assert_eq!(single_credential.id, credential.id);
}

#[tokio::test]
async fn test_holder_accept_credential_autogenerate_holder_binding() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let credential = generic_credential_did_with_holder_identifier();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        access_token: None,
        batch_size: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: credential
            .schema
            .as_ref()
            .unwrap()
            .schema_id()
            .await
            .unwrap(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{"credential": "credential"}],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_accepted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });
    key_provider.expect_get_key_storage().returning(move |_| {
        let mut storage = MockKeyStorage::new();
        storage
            .expect_get_capabilities()
            .returning(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![KeyAlgorithmType::Ecdsa],
            });

        storage.expect_generate().returning(|_, _, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: Some(vec![]),
            })
        });

        Ok(Arc::new(storage))
    });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });
    key_algorithm_provider
        .expect_ordered_by_holder_priority()
        .returning(|| vec![(KeyAlgorithmType::Ecdsa, Arc::new(MockKeyAlgorithm::new()))]);

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_ordered_by_priority()
        .once()
        .returning(|| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            vec![(KeySecurityLevelType::Basic, Arc::new(security))]
        });

    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_create_key()
        .once()
        .returning(|key| Ok(key.id));

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_create_local_identifier()
        .once()
        .returning(|_, request, _| {
            let_assert!(CreateLocalIdentifierRequest::Key(key) = request);
            Ok(Identifier {
                r#type: IdentifierType::Key,
                key: Some(key),
                ..dummy_identifier()
            })
        });

    let issuer_identifier = dummy_identifier();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .return_once({
            let identifier = issuer_identifier.clone();
            move |_, _, _| Ok((identifier, RemoteIdentifierRelation::Key(dummy_key())))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(|history| {
            assert_eq!(history.action, HistoryAction::TrustResolved);
            true
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_repository,
        identifier_creator,
        key_algorithm_provider,
        key_security_level_provider,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let issuer_response = openid_provider
        .holder_accept_credential(interaction, None, None)
        .await
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );
    assert!(issuer_response.batch_items.is_empty());

    let create_credential = issuer_response.main_credential.credential;
    assert_eq!(create_credential.id, credential.id);
    assert_eq!(create_credential.r#type, CredentialType::Single);
    assert_eq!(
        create_credential.issuer_identifier.as_ref().unwrap().id,
        issuer_identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_credential_batch_autogenerated_binding() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let credential = generic_credential_did();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        access_token: None,
        batch_size: Some(2),
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: credential
            .schema
            .as_ref()
            .unwrap()
            .schema_id()
            .await
            .unwrap(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [
                    { "credential": "credential1"},
                    { "credential": "credential2"}
                ],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_accepted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let holder_keys = Arc::new(Mutex::new(vec![]));

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_create_local_identifier()
        .times(2)
        .returning({
            let holder_keys = holder_keys.clone();
            move |_, request, _| {
                let_assert!(CreateLocalIdentifierRequest::Key(key) = request);

                let mut guard = holder_keys.lock().unwrap();
                guard.push(key.clone());

                Ok(Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key),
                    ..dummy_identifier()
                })
            }
        });

    let issuer_identifier = credential.issuer_identifier.clone().unwrap();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .times(2)
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .returning({
            let identifier = issuer_identifier.clone();
            move |_, _, _| {
                Ok((
                    identifier.clone(),
                    RemoteIdentifierRelation::Key(dummy_key()),
                ))
            }
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().times(2).returning({
        let clone = credential.clone();
        let holder_keys = holder_keys.clone();
        move |_, _, _| {
            let mut guard = holder_keys.lock().unwrap();
            let key = guard.pop().unwrap();

            Ok(Credential {
                id: Uuid::new_v4().into(),
                holder_identifier: Some(Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key),
                    ..dummy_identifier()
                }),
                ..clone.clone()
            })
        }
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });
    key_provider.expect_get_key_storage().returning(move |_| {
        let mut storage = MockKeyStorage::new();
        storage
            .expect_get_capabilities()
            .returning(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![KeyAlgorithmType::Ecdsa],
            });

        storage.expect_generate().returning(|_, _, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: Some(vec![]),
            })
        });

        Ok(Arc::new(storage))
    });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });
    key_algorithm_provider
        .expect_ordered_by_holder_priority()
        .returning(|| vec![(KeyAlgorithmType::Ecdsa, Arc::new(MockKeyAlgorithm::new()))]);

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_ordered_by_priority()
        .returning(|| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            vec![(KeySecurityLevelType::Basic, Arc::new(security))]
        });

    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_create_key()
        .times(2)
        .returning(|key| Ok(key.id));

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .times(1)
        .withf(|history| {
            assert_eq!(history.action, HistoryAction::TrustResolved);
            true
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_repository,
        identifier_creator,
        key_algorithm_provider,
        key_security_level_provider,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let issuer_response = openid_provider
        .holder_accept_credential(interaction, None, None)
        .await
        .unwrap();
    let main_credential = &issuer_response.main_credential;
    assert_eq!(
        main_credential.credential.r#type,
        CredentialType::BatchParent
    );
    assert_eq!(main_credential.serialized, None);

    let credentials = &issuer_response.batch_items;
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0].serialized, Some("credential1".into()));
    assert_eq!(credentials[1].serialized, Some("credential2".into()));
    assert_eq!(credentials[0].credential.r#type, CredentialType::BatchItem);
    assert_eq!(credentials[1].credential.r#type, CredentialType::BatchItem);
    assert_eq!(
        credentials[0]
            .credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .id,
        issuer_identifier.id
    );
    assert_eq!(
        credentials[1]
            .credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .id,
        issuer_identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_credential_batch_manual_binding() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let key = Key {
        storage_type: "INTERNAL".to_string(),
        ..dummy_key()
    };
    let mut credential = generic_credential_did_with_holder_identifier();
    credential.holder_identifier.as_mut().unwrap().key = Some(key.clone());

    let credential_configuration_id = credential
        .schema
        .as_ref()
        .unwrap()
        .schema_id()
        .await
        .unwrap();
    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        access_token: None,
        batch_size: Some(2),
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: credential_configuration_id.clone(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .and({
            let credential_configuration_id = credential_configuration_id.clone();
            move |request: &wiremock::Request| {
                let request: OpenID4VCICredentialRequestDTO = request.body_json().unwrap();
                let OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(config_id) =
                    &request.credential
                else {
                    panic!("invalid request: {request:?}");
                };
                assert_eq!(config_id, &credential_configuration_id);

                let OpenID4VCICredentialRequestProofs::Jwt(proofs) =
                    &request.proofs.as_ref().unwrap()
                else {
                    panic!("invalid request: {request:?}");
                };
                assert_eq!(proofs.len(), 1);

                true
            }
        })
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{ "credential": "credential1"}],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_accepted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().times(1).returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });
    key_provider.expect_get_key_storage().returning(move |_| {
        let mut storage = MockKeyStorage::new();
        storage
            .expect_get_capabilities()
            .returning(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![KeyAlgorithmType::Ecdsa],
            });

        storage.expect_generate().returning(|_, _, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: Some(vec![]),
            })
        });

        Ok(Arc::new(storage))
    });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });
    key_algorithm_provider
        .expect_ordered_by_holder_priority()
        .returning(|| vec![(KeyAlgorithmType::Ecdsa, Arc::new(MockKeyAlgorithm::new()))]);

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_ordered_by_priority()
        .returning(|| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            vec![(KeySecurityLevelType::Basic, Arc::new(security))]
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    let issuer_identifier = dummy_identifier();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .times(1)
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .returning({
            let identifier = issuer_identifier.clone();
            move |_, _, _| {
                Ok((
                    identifier.clone(),
                    RemoteIdentifierRelation::Key(dummy_key()),
                ))
            }
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .times(1)
        .withf(|history| {
            assert_eq!(history.action, HistoryAction::TrustResolved);
            true
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        identifier_creator,
        key_algorithm_provider,
        key_security_level_provider,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential1".into())
    );

    assert!(issuer_response.batch_items.is_empty());
    let main_credential = issuer_response.main_credential.credential;
    assert_eq!(
        main_credential.issuer_identifier.as_ref().unwrap().id,
        issuer_identifier.id
    );
}

#[tokio::test]
async fn test_holder_reject_credential() {
    let mock_server = MockServer::start().await;
    let mut did_method_provider = MockDidMethodProvider::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let encryption = SecretSlice::from(vec![0; 32]);

    let credential = {
        let mut credential = generic_credential_did();
        credential.state = CredentialStateEnum::Accepted;
        credential.key = Some(dummy_key());

        let interaction_data = HolderInteractionData {
            issuer_url: mock_server.uri(),
            credential_endpoint: format!("{}/credential", mock_server.uri()),
            token_endpoint: Some(format!("{}/token", mock_server.uri())),
            nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
            notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
            challenge_endpoint: None,
            grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
                OpenID4VCIPreAuthorizedCodeGrant {
                    pre_authorized_code: "code".to_string(),
                    tx_code: None,
                    authorization_server: None,
                },
            )),
            batch_size: None,
            access_token: None,
            access_token_expires_at: None,
            refresh_token: Some(
                encrypt_data(&SecretSlice::from(vec![0; 32]), &encryption).unwrap(),
            ),
            refresh_token_expires_at: None,
            token_endpoint_auth_methods_supported: None,
            client_attestation_pop_signing_alg_values_supported: None,
            cryptographic_binding_methods_supported: None,
            proof_types_supported: None,
            credential_signing_alg_values_supported: None,
            continue_issuance: None,
            credential_configuration_id: credential
                .schema
                .as_ref()
                .unwrap()
                .schema_id()
                .await
                .unwrap(),
            credential_metadata: None,
            notification_id: Some("notification_id".to_string()),
            protocol: "OPENID4VCI_FINAL1".to_string(),
            format: "jwt_vc_json".to_string(),
            access_certificate: None,
            relying_party_id: None,
            national_registry_url: None,
            registration_certificate: None,
            national_registry_data: None,
            relying_party_name: None,
            trust_resolution: TrustResolutionResult::Unknown,
            trust_mode: TrustMode::Disabled,
            disclosure_policy: None,
        };

        credential.interaction = Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            data: Some(serde_json::to_vec(&interaction_data).unwrap()),
            organisation: Some(dummy_organisation(None)),
            nonce_id: None,
            interaction_type: InteractionType::Issuance,
            expires_at: None,
        });

        credential
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_deleted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|_| {
            let mut algorithm = MockKeyAlgorithm::new();
            algorithm.expect_generate_key().returning(|| {
                let mut private_key = MockSignaturePrivateKeyHandle::default();

                private_key
                    .expect_sign()
                    .returning(|_| Ok("signature".as_bytes().to_vec()));

                let mut public_key = MockSignaturePublicKeyHandle::default();
                public_key.expect_as_jwk().return_once(|| {
                    Ok(PublicJwk::Ec(PublicJwkEc {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "P-256".to_string(),
                        x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                        y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                    }))
                });

                Ok(GeneratedKey {
                    key: KeyHandle::SignatureOnly(SignatureKeyHandle::WithPrivateKey {
                        private: Arc::new(private_key),
                        public: Arc::new(public_key),
                    }),
                    public: vec![],
                    private: vec![].into(),
                })
            });

            algorithm
                .expect_issuance_jose_alg_id()
                .returning(|| "ES256".to_string());

            Ok(Arc::new(algorithm))
        });

    did_method_provider.expect_get_did_method().returning(|_| {
        let mut method = MockDidMethod::new();
        method.expect_create().returning(|_, _, _| {
            Ok(DidCreated {
                did: dummy_did().did,
                log: None,
            })
        });
        method
            .expect_get_reference_for_key()
            .return_once(|_| Ok("1".to_string()));
        Ok((Arc::new(method), crate::config::core_config::DidType::Key))
    });

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let openid_provider = setup_protocol(TestInputs {
        did_method_provider,
        key_algorithm_provider,
        interaction_repository,
        holder_wallet_unit_repository,
        config: dummy_config(),
        ..Default::default()
    });

    openid_provider
        .holder_reject_credential(credential)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_with_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(
        generic_credential_did(),
        Some("did:example:123".to_string()),
    )
    .await;
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_without_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(generic_credential_did(), None).await;
}

async fn inner_test_handle_invitation_credential_by_ref_success(
    credential: Credential,
    issuer_did: Option<String>,
) {
    let mock_server = MockServer::start().await;
    let issuer_url = Url::from_str(&mock_server.uri()).unwrap();

    let credential_schema_id = credential.schema.clone().unwrap().id;
    let credential_issuer = format!("{issuer_url}ssi/openid4vci/final-1.0/{credential_schema_id}");

    let mut credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids" : [credential_schema_id],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
        },
        "credential_subject": {
            "keys": {
                "NUMBER": {
                    "value": "123",
                }
            },
        }
    });
    if let Some(ref issuer_did) = issuer_did {
        credential_offer
            .as_object_mut()
            .unwrap()
            .insert("issuer_did".into(), Value::String(issuer_did.to_owned()));
    };

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/final-1.0/{}/offer/{}",
            credential_schema_id, credential.id
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(credential_offer))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();
    metadata_cache
            .expect_get()
            .with(eq(format!(
                "{issuer_url}.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
            )),
            eq("application/json"))
            .once()
            .returning({
                    let credential_issuer = credential_issuer.clone();
                    move |_,_| Ok(json!({
                        "authorization_endpoint": format!("{credential_issuer}/authorize"),
                        "grant_types_supported": [
                            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                        ],
                        "id_token_signing_alg_values_supported": [],
                        "issuer": credential_issuer,
                        "jwks_uri": format!("{credential_issuer}/jwks"),
                        "response_types_supported": [
                            "token"
                        ],
                        "subject_types_supported": [
                            "public"
                        ],
                        "token_endpoint": format!("{credential_issuer}/token")
                    }).to_string().into_bytes())
                });

    metadata_cache
        .expect_get()
        .with(eq(format!(
            "{issuer_url}.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )),
    eq("application/json"))
        .once()
        .returning(move |_,_| Ok(json!({
            "credential_endpoint": format!("{credential_issuer}/credential"),
            "credential_issuer": credential_issuer,
            "nonce_endpoint": format!("{credential_issuer}/nonce"),
            "credential_configurations_supported": {
                credential_schema_id.to_string(): {
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "address": {
                                "value_type": "STRING",
                            }
                        }
                    },
                    "format": "vc+sd-jwt",
                }
            }
        }).to_string().into_bytes()));

    let capture_integration_id = Arc::new(Mutex::new(None));
    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_create_interaction()
        .times(1)
        .returning({
            let capture_integration_id = capture_integration_id.clone();
            move |i: Interaction| {
                let mut guard = capture_integration_id.lock().unwrap();
                *guard = Some(i.id);
                Ok(i.id)
            }
        });

    let url = Url::parse(&format!("openid-credential-offer://?credential_offer_uri=http%3A%2F%2F{}%2Fssi%2Fopenid4vci%2Ffinal-1.0%2F{}%2Foffer%2F{}", issuer_url.authority(), credential_schema_id, credential.id)).unwrap();

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        interaction_repository,
        ..Default::default()
    });
    let result = protocol
        .holder_handle_invitation(url, dummy_organisation(None), None)
        .await
        .unwrap();

    let InvitationResponseEnum::Credential {
        interaction_id,
        key_storage_security,
        ..
    } = result
    else {
        panic!("Invalid response type");
    };

    assert_eq!(
        capture_integration_id.lock().unwrap().unwrap(),
        interaction_id
    );
    assert_eq!(key_storage_security, None);
}

#[tokio::test]
async fn test_handle_invitation_signed_metadata() {
    let mut client = MockHttpClient::new();

    let credential_offer = json!({
        "credential_issuer": "http://issuer.url",
        "credential_configuration_ids" : ["doctype"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
        }
    });

    client
        .expect_get()
        .with(eq("http://issuer.url/offer"))
        .once()
        .return_once(|url| {
            let mut client = MockHttpClient::new();
            client
                .expect_send()
                .once()
                .return_once(move |url, body, headers, method, timeout| {
                    Ok(Response {
                        body: credential_offer.to_string().as_bytes().to_vec(),
                        headers: Default::default(),
                        status: StatusCode(200),
                        request: Request {
                            body,
                            headers: headers.unwrap_or_default(),
                            method,
                            url: url.to_string(),
                            timeout,
                        },
                    })
                });

            RequestBuilder::new(
                Arc::new(client),
                crate::proto::http_client::Method::Get,
                url,
            )
        });

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();

    let access_certificate = "MIIDDDCCArKgAwIBAgIUG8SguUrbgpJUvd6v+07Sp8utLfQwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI1MDQxMDA2NDU1OFoXDTI3MDQxMDA2NDU1N1owVzEdMBsGA1UEAwwURVVESSBSZW1vdGUgVmVyaWZpZXIxCjAIBgNVBAUTATExHTAbBgNVBAoMFEVVREkgUmVtb3RlIFZlcmlmaWVyMQswCQYDVQQGEwJVVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOciV42mIT8nQMAN8kW9CHNUTYwkieem5hl1QsLf62kEbbZh6wul5iL28g/A3ZqcTX9XoLnw/nvJ8/HRp3+95eKjggFVMIIBUTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFGLHlEcovQ+iFiCnmsJJlETxAdPHMDkGA1UdEQQyMDCBEm5vLXJlcGx5QGV1ZGl3LmRldoIadmVyaWZpZXItYmFja2VuZC5ldWRpdy5kZXYwEgYDVR0lBAswCQYHKIGMXQUBBjBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAyLmNybDAdBgNVHQ4EFgQUgAh9KsoYXYK8jndUbFQEtfDsHjYwDgYDVR0PAQH/BAQDAgeAMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwIDSAAwRQIgDFCgyEjGnJS25n/FfdP7HX0elz7C2q4uUQ/7Zcrl0QYCIQC/rrJpQ5sF1O4aiHejIPPLuO3JjdrLJPZSA+FQH+eIrA==";
    let registration_certificate = "registration-certificate";
    let jwt = {
        let header = json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg" : "ES256",
            "x5c": [access_certificate]
        });
        let payload = json!({
            "credential_endpoint": "http://issuer.url/credential",
            "credential_issuer": "http://issuer.url",
            "nonce_endpoint": "http://issuer.url/nonce",
            "credential_configurations_supported": {
                "doctype": {
                    "format": "mso_mdoc",
                    "doctype": "doctype",
                    "disclosure_policy": {
                        "id": "policy-id",
                        "policy": "none",
                        "url": "https://policy.url"
                    }
                }
            },
            "issuer_info": [{
                "format": "registration_cert",
                "data": registration_certificate
            }]
        });

        let header =
            Base64UrlSafeNoPadding::encode_to_string(header.to_string().as_bytes()).unwrap();
        let payload =
            Base64UrlSafeNoPadding::encode_to_string(payload.to_string().as_bytes()).unwrap();
        format!("{header}.{payload}.c2lnbmF0dXJl")
    };

    metadata_cache
        .expect_get()
        .with(
            eq("http://issuer.url/.well-known/openid-credential-issuer"),
            eq("application/jwt"),
        )
        .once()
        .return_once(move |_, _| Ok(jwt.as_bytes().to_vec()));

    metadata_cache
        .expect_get()
        .with(
            eq("http://issuer.url/.well-known/oauth-authorization-server"),
            eq("application/json"),
        )
        .once()
        .return_once(|_, _| {
            Ok(json!({
                "authorization_endpoint": "http://issuer.url/authorize",
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": "http://issuer.url",
                "jwks_uri": "http://issuer.url/jwks",
                "token_endpoint": "http://issuer.url/token",
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ]
            })
            .to_string()
            .as_bytes()
            .to_vec())
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("ES256"))
        .once()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .once()
                .return_const(KeyAlgorithmType::Ecdsa);
            Some((KeyAlgorithmType::Ecdsa, Arc::new(key_algorithm)))
        });

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .once()
        .return_once(|_, _| {
            let mut signature_handle = MockSignaturePublicKeyHandle::new();
            signature_handle
                .expect_verify()
                .once()
                .return_once(|_, _| Ok(()));

            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "test".to_string(),
                    not_before: crate::clock::now_utc(),
                    not_after: crate::clock::now_utc(),
                    issuer: "Test Issuer".to_string(),
                    subject: "Test Subject".to_string(),
                    fingerprint: "test".to_string(),
                    extensions: vec![],
                },
                subject_common_name: Some("Test".to_string()),
                subject_key_identifier: None,
                public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    signature_handle,
                ))),
            })
        });

    let rp_id = "rp_id";
    let mut wrp_validator = MockWRPValidator::new();
    wrp_validator
        .expect_wallet_trust_mode()
        .once()
        .return_once(|_| Ok(TrustMode::TrustMandatory));
    wrp_validator
        .expect_validate_access_certificate()
        .once()
        .return_once(|_, _| {
            Ok(AccessCertificateResult {
                trust_entity: None,
                relying_party_id: rp_id.to_string(),
                registry_url: None,
            })
        });
    wrp_validator
        .expect_validate_registration_certificate()
        .with(eq(registration_certificate), eq(rp_id), always(), always())
        .once()
        .return_once(|_, _, _, _| {
            Ok(RegistrationCertificateResult {
                trust_entity: None,
                payload: JWTPayload {
                    issued_at: Some(crate::clock::now_utc()),
                    expires_at: None,
                    invalid_before: None,
                    issuer: None,
                    subject: Some(rp_id.to_string()),
                    audience: None,
                    jwt_id: None,
                    proof_of_possession_key: None,
                    custom: registration_certificate::model::Payload {
                        name: "".to_string(),
                        sub_ln: None,
                        sub_gn: None,
                        sub_fn: None,
                        country: "".to_string(),
                        registry_uri: Url::parse("https://example.com").unwrap(),
                        service_descriptions: vec![],
                        entitlements: vec![],
                        privacy_policy: Url::parse("https://example.com").unwrap(),
                        info_uri: Url::parse("https://example.com").unwrap(),
                        supervisory_authority: SupervisoryAuthority {
                            email: "".to_string(),
                            phone: "".to_string(),
                            uri: "".to_string(),
                        },
                        policy_id: vec![],
                        certificate_policy: Url::parse("https://example.com").unwrap(),
                        status: Status {
                            status_list: HashMap::new(),
                        },
                        provides_attestations: Some(vec![
                            registration_certificate::model::Credential {
                                format: dcql::CredentialFormat::MsoMdoc(MsoMdocMeta {
                                    doctype_value: "doctype".to_string(),
                                }),
                                claim: None,
                            },
                        ]),
                        credentials: None,
                        purpose: None,
                        intended_use_id: Some("intended_use_id".to_string()),
                        public_body: None,
                        support_uri: Url::parse("https://example.com").unwrap(),
                        intermediary: None,
                    },
                },
            })
        });

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_create_interaction()
        .withf(move |interaction| {
            let data: HolderInteractionData =
                serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();

            let pem_chain = x5c_into_pem_chain(&[access_certificate.to_string()]).unwrap();

            assert_eq!(data.access_certificate.unwrap(), pem_chain);
            assert_eq!(
                data.registration_certificate.unwrap(),
                registration_certificate
            );
            assert_eq!(
                data.disclosure_policy.unwrap(),
                DisclosurePolicy {
                    id: "policy-id".to_string(),
                    policy: PolicyType::None,
                    description: None,
                    url: Some("https://policy.url".to_string()),
                }
            );
            true
        })
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        key_algorithm_provider,
        certificate_validator,
        wrp_validator,
        interaction_repository,
        client: Some(client),
        params: Some({
            let mut params = test_params("openid-credential-offer");
            params["requestSignedMetadata"] = json!(true);
            params
        }),
        ..Default::default()
    });

    let url = Url::parse(
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fissuer.url%2Foffer",
    )
    .unwrap();
    let result = protocol
        .holder_handle_invitation(url, dummy_organisation(None), None)
        .await
        .unwrap();

    assert2::assert!(
        let InvitationResponseEnum::Credential {..} = result
    );
}

#[tokio::test]
async fn test_continue_issuance_with_scope_success() {
    inner_continue_issuance_test(true, false).await;
}

#[tokio::test]
async fn test_continue_issuance_with_credential_configuration_ids_success() {
    inner_continue_issuance_test(false, true).await;
}

#[tokio::test]
async fn test_continue_issuance_with_scope_and_credential_configuration_ids_success() {
    inner_continue_issuance_test(true, true).await;
}

async fn inner_continue_issuance_test(with_scope: bool, with_credential_configuration_ids: bool) {
    let credential = generic_credential_did();

    let credential_schema_id = credential.schema.clone().unwrap().id;
    let credential_issuer =
        format!("http://issuer/ssi/openid4vci/final-1.0/{credential_schema_id}");

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();

    metadata_cache
        .expect_get()
        .with(eq(format!("http://issuer/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}")),
    eq("application/json"))
        .once()
        .returning({
            let credential_issuer = credential_issuer.clone();
            move |_,_| {
                Ok(json!({
                    "authorization_endpoint": format!("{credential_issuer}/authorize"),
                    "grant_types_supported": [
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                    ],
                    "id_token_signing_alg_values_supported": [],
                    "issuer": credential_issuer,
                    "jwks_uri": format!("{credential_issuer}/jwks"),
                    "response_types_supported": [
                        "token"
                    ],
                    "subject_types_supported": [
                        "public"
                    ],
                    "token_endpoint": format!("{credential_issuer}/token")
                })
                .to_string()
                .into_bytes())
            }
        });

    metadata_cache
        .expect_get()
        .with(eq(format!(
            "http://issuer/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )),
        eq("application/json"))
        .once()
        .returning({
            let credential_issuer = credential_issuer.clone();
            move |_,_| {
                Ok(json!({
                    "credential_endpoint": format!("{credential_issuer}/credential"),
                    "credential_issuer": credential_issuer,
                    "nonce_endpoint": format!("{credential_issuer}/nonce"),
                    "credential_configurations_supported": {
                        credential_schema_id.to_string(): {
                            "credential_definition": {
                                "type": [
                                    "VerifiableCredential"
                                ],
                                "credentialSubject" : {
                                    "address": {
                                        "value_type": "STRING",
                                    }
                                }
                            },
                            "format": "vc+sd-jwt",
                            "scope": "testScope",
                        }
                  }
                })
                .to_string()
                .into_bytes())
            }
        });

    let capture_integration_id = Arc::new(Mutex::new(None));
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .times(1)
        .returning({
            let capture_integration_id = capture_integration_id.clone();
            move |i: Interaction| {
                let mut guard = capture_integration_id.lock().unwrap();
                *guard = Some(i.id);
                Ok(i.id)
            }
        });

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        interaction_repository,
        ..Default::default()
    });

    // when

    let scope = if with_scope {
        vec!["testScope".to_string()]
    } else {
        Vec::new()
    };

    let credential_configuration_ids = if with_credential_configuration_ids {
        vec![credential_schema_id.to_string()]
    } else {
        Vec::new()
    };

    let result = protocol
        .holder_continue_issuance(
            ContinueIssuanceDTO {
                credential_issuer,
                authorization_code: "authorization_code".to_string(),
                client_id: "testClientId".to_string(),
                redirect_uri: None,
                scope,
                credential_configuration_ids,
                code_verifier: None,
                authorization_server: None,
            },
            dummy_organisation(None),
        )
        .await
        .unwrap();

    assert_eq!(
        capture_integration_id.lock().unwrap().unwrap(),
        result.interaction_id
    );
}

#[tokio::test]
async fn test_can_handle_issuance_success_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let test_url = format!(
        "{url_scheme}://?credential_offer_uri=http%3A%2F%2Fissuer.com%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965",
    );
    assert!(protocol.holder_can_handle(&test_url.parse().unwrap()))
}

#[tokio::test]
async fn test_can_handle_issuance_fail_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";
    let other_url_scheme = "my-different-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let test_url = format!(
        "{other_url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
    assert!(!protocol.holder_can_handle(&test_url.parse().unwrap()))
}

#[tokio::test]
async fn test_generate_share_credentials_custom_scheme() {
    let credential = generic_credential_did();
    let url_scheme = "my-custom-scheme";
    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    assert!(result.url.starts_with(url_scheme));
}

#[tokio::test]
async fn test_holder_accept_credential_fails_without_wallet_unit_id_when_key_attestation_required()
{
    let credential = generic_credential_did();

    let mut proof_types = IndexMap::new();
    proof_types.insert(
        "jwt".to_string(),
        OpenID4VCIProofTypeSupported {
            proof_signing_alg_values_supported: vec!["ES256".to_string()],
            key_attestations_required: Some(OpenID4VCIKeyAttestationsRequired {
                key_storage: vec![KeyStorageSecurityLevel::Basic],
                user_authentication: vec![],
            }),
        },
    );

    let interaction_data = HolderInteractionData {
        issuer_url: "http://issuer".to_string(),
        credential_endpoint: "http://issuer/credential".to_string(),
        token_endpoint: Some("http://issuer/token".to_string()),
        nonce_endpoint: Some("http://issuer/nonce".to_string()),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: Some(proof_types),
        continue_issuance: None,
        credential_configuration_id: credential
            .schema
            .as_ref()
            .unwrap()
            .schema_id()
            .await
            .unwrap(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            security.expect_get_priority().return_const(0u64);
            security
                .expect_get_capabilities()
                .returning(|| KeySecurityLevelCapabilities {
                    openid_security_level: vec![KeyStorageSecurityLevel::Basic],
                });
            Ok(Arc::new(security))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let openid_provider = setup_protocol(TestInputs {
        key_security_level_provider,
        holder_wallet_unit_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let key = Key {
        storage_type: "INTERNAL".to_string(),
        ..dummy_key()
    };
    let result = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await;

    let err = result.unwrap_err();
    assert!(
        err.to_string()
            .contains("key storage attestation requires active holder wallet unit id"),
    );
}

#[tokio::test]
async fn test_holder_accept_credential_succeeds_with_wallet_unit_id_when_key_attestation_required()
{
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let key = Key {
        storage_type: "INTERNAL".to_string(),
        ..dummy_key()
    };
    let mut credential = generic_credential_did_with_holder_identifier();
    credential.holder_identifier.as_mut().unwrap().key = Some(key.clone());

    let mut proof_types = IndexMap::new();
    proof_types.insert(
        "jwt".to_string(),
        OpenID4VCIProofTypeSupported {
            proof_signing_alg_values_supported: vec!["ES256".to_string()],
            key_attestations_required: Some(OpenID4VCIKeyAttestationsRequired {
                key_storage: vec![KeyStorageSecurityLevel::Basic],
                user_authentication: vec![],
            }),
        },
    );

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
        credential_signing_alg_values_supported: None,
        proof_types_supported: Some(proof_types),
        continue_issuance: None,
        credential_configuration_id: credential
            .schema
            .as_ref()
            .unwrap()
            .schema_id()
            .await
            .unwrap(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{"credential": "credential"}],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_accepted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            security.expect_get_priority().return_const(0u64);
            security
                .expect_get_capabilities()
                .returning(|| KeySecurityLevelCapabilities {
                    openid_security_level: vec![KeyStorageSecurityLevel::Basic],
                });
            Ok(Arc::new(security))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| {
            Ok(GetListResponse::one(HolderWalletInstance {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                wallet_provider_type: WalletProviderType::ProcivisOne,
                wallet_provider_name: "provider".to_string(),
                wallet_provider_url: "provider.url".to_string(),
                provider_wallet_unit_id: Uuid::new_v4().into(),
                status: WalletInstanceStatus::Active,
                organisation: dummy_organisation(None).into(),
                authentication_key: None,
                wallet_unit_attestations: None,
                trusted_rp_required: false,
                nonce: None,
                user_nonce: None,
            }))
        });

    let mut holder_wallet_unit_proto = MockHolderWalletUnitProto::new();
    holder_wallet_unit_proto
        .expect_issue_wallet_attestations()
        .once()
        .returning(|_, _| {
            Ok(IssuedWalletUnitAttestations {
                provider_response: IssueWalletUnitAttestationResponseDTO {
                    wia: vec![],
                    wua: vec!["wua_attestation_jwt".to_string()],
                },
                wia_pop_key: None,
            })
        });

    let identifier = dummy_identifier();
    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .return_once({
            let identifier = identifier.clone();
            move |_, _, _| Ok((identifier, RemoteIdentifierRelation::Key(dummy_key())))
        });

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(|history| {
            assert_eq!(history.action, HistoryAction::TrustResolved);
            true
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        key_security_level_provider,
        holder_wallet_unit_proto,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );
}

async fn interaction_with_metadata(
    credential: &Credential,
    credential_metadata: OpenID4VCICredentialMetadataResponseDTO,
    mock_server_uri: &str,
) -> Interaction {
    let interaction_data = HolderInteractionData {
        issuer_url: mock_server_uri.to_owned(),
        credential_endpoint: format!("{mock_server_uri}/credential"),
        token_endpoint: Some(format!("{mock_server_uri}/token")),
        nonce_endpoint: Some(format!("{mock_server_uri}/nonce")),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: "CredentialSchemaId".to_owned(),
        credential_metadata: Some(credential_metadata),
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: None,
    };

    Interaction {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    }
}

#[tokio::test]
async fn test_holder_accept_credential_stores_all_translations_from_metadata() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut credential_schema_importer = MockCredentialSchemaImporter::new();

    let credential = generic_credential_key();

    let credential_metadata = OpenID4VCICredentialMetadataResponseDTO {
        display: Some(vec![
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
                name: "My Credential".to_string(),
                locale: Some("en".to_string()),
                description: Some("English description".to_string()),
                ..Default::default()
            },
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
                name: "Mein Ausweis".to_string(),
                locale: Some("de".to_string()),
                description: None,
                ..Default::default()
            },
        ]),
        claims: None,
    };

    let interaction =
        interaction_with_metadata(&credential, credential_metadata, &mock_server.uri()).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "nonce"})))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{"credential": "credential"}]
        })))
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(|_, _| Ok(None));

    let captured_schema: Arc<Mutex<Option<CredentialSchema>>> = Arc::new(Mutex::new(None));
    let captured_schema_clone = captured_schema.clone();

    credential_schema_importer
        .expect_import_credential_schema()
        .once()
        .returning(move |schema| {
            *captured_schema_clone.lock().unwrap() = Some(schema.clone());
            Ok(schema)
        });

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));
            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));
            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .return_once(|_, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut config = dummy_config();
    config.global_settings.default_language = "en".to_string();

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        credential_schema_importer: Some(credential_schema_importer),
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config,
        ..Default::default()
    });

    // WHEN
    let key = dummy_key();
    openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await
        .unwrap();

    // THEN
    let schema = captured_schema.lock().unwrap().take().unwrap();
    let translations = schema.translations.as_ref().await.unwrap();
    assert_eq!(
        translations.len(),
        3,
        "expected Name(en), Description(en), Name(de)"
    );

    let en_name = translations
        .iter()
        .find(|t| t.lang == "en" && t.field == LocalizedTextField::Name)
        .expect("en Name translation missing");
    assert_eq!(en_name.value, "My Credential");
    assert_eq!(
        en_name.entity_type,
        LocalizedTextEntityType::CredentialSchema
    );

    let en_desc = translations
        .iter()
        .find(|t| t.lang == "en" && t.field == LocalizedTextField::Description)
        .expect("en Description translation missing");
    assert_eq!(en_desc.value, "English description");

    let de_name = translations
        .iter()
        .find(|t| t.lang == "de" && t.field == LocalizedTextField::Name)
        .expect("de Name translation missing");
    assert_eq!(de_name.value, "Mein Ausweis");
}

#[tokio::test]
async fn test_holder_accept_credential_uses_default_language_for_display_without_locale() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut credential_schema_importer = MockCredentialSchemaImporter::new();

    let credential = generic_credential_key();

    let credential_metadata = OpenID4VCICredentialMetadataResponseDTO {
        display: Some(vec![
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
                name: "Mein Ausweis".to_string(),
                locale: None, // no locale — should fall back to default_language
                description: None,
                ..Default::default()
            },
        ]),
        claims: None,
    };

    let interaction =
        interaction_with_metadata(&credential, credential_metadata, &mock_server.uri()).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "nonce"})))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{"credential": "credential"}]
        })))
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(|_, _| Ok(None));

    let captured_schema: Arc<Mutex<Option<CredentialSchema>>> = Arc::new(Mutex::new(None));
    let captured_schema_clone = captured_schema.clone();

    credential_schema_importer
        .expect_import_credential_schema()
        .once()
        .returning(move |schema| {
            *captured_schema_clone.lock().unwrap() = Some(schema.clone());
            Ok(schema)
        });

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));
            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));
            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .return_once(|_, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut config = dummy_config();
    config.global_settings.default_language = "fr".to_string(); // custom default language

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        credential_schema_importer: Some(credential_schema_importer),
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config,
        ..Default::default()
    });

    // WHEN
    let key = dummy_key();
    openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await
        .unwrap();

    // THEN
    let schema = captured_schema.lock().unwrap().take().unwrap();
    let translations = schema.translations.as_ref().await.unwrap();
    assert_eq!(translations.len(), 1);

    let translation = &translations[0];
    assert_eq!(
        translation.lang, "fr",
        "locale-less display should use default_language"
    );
    assert_eq!(translation.field, LocalizedTextField::Name);
    assert_eq!(translation.value, "Mein Ausweis");
}

#[tokio::test]
async fn test_holder_accept_credential_stores_claim_schema_translations_from_metadata() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut credential_schema_importer = MockCredentialSchemaImporter::new();

    // generic_credential_key() has a claim schema with key "NUMBER"
    let credential = generic_credential_key();

    let credential_metadata = OpenID4VCICredentialMetadataResponseDTO {
        display: Some(vec![
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
                name: "My Credential".to_string(),
                locale: Some("en".to_string()),
                ..Default::default()
            },
        ]),
        claims: Some(vec![OpenID4VCICredentialMetadataClaimResponseDTO {
            path: vec!["NUMBER".to_string()],
            display: Some(vec![
                OpenID4VCIIssuerMetadataClaimDisplay {
                    name: Some("Number".to_string()),
                    locale: Some("en".to_string()),
                },
                OpenID4VCIIssuerMetadataClaimDisplay {
                    name: Some("Nummer".to_string()),
                    locale: Some("de".to_string()),
                },
            ]),
            mandatory: None,
            additional_values: None,
        }]),
    };

    let interaction =
        interaction_with_metadata(&credential, credential_metadata, &mock_server.uri()).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "nonce"})))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{"credential": "credential"}]
        })))
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(|_, _| Ok(None));

    let captured_schema: Arc<Mutex<Option<CredentialSchema>>> = Arc::new(Mutex::new(None));
    let captured_schema_clone = captured_schema.clone();

    credential_schema_importer
        .expect_import_credential_schema()
        .once()
        .returning(move |schema| {
            *captured_schema_clone.lock().unwrap() = Some(schema.clone());
            Ok(schema)
        });

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));
            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));
            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .return_once(|_, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut config = dummy_config();
    config.global_settings.default_language = "en".to_string();

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        credential_schema_importer: Some(credential_schema_importer),
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config,
        ..Default::default()
    });

    // WHEN
    let key = dummy_key();
    openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await
        .unwrap();

    // THEN
    let schema = captured_schema.lock().unwrap().take().unwrap();
    let claim_schemas = schema.claim_schemas.as_ref().await.unwrap();
    let number_claim = claim_schemas
        .iter()
        .find(|cs| cs.key == "NUMBER")
        .expect("NUMBER claim schema missing");

    let claim_translations = number_claim.translations.as_ref().await.unwrap();
    assert_eq!(
        claim_translations.len(),
        2,
        "expected Name(en) and Name(de) for NUMBER claim"
    );

    let en = claim_translations
        .iter()
        .find(|t| t.lang == "en")
        .expect("en translation missing");
    assert_eq!(en.field, LocalizedTextField::Name);
    assert_eq!(en.value, "Number");
    assert_eq!(en.entity_type, LocalizedTextEntityType::ClaimSchema);

    let de = claim_translations
        .iter()
        .find(|t| t.lang == "de")
        .expect("de translation missing");
    assert_eq!(de.field, LocalizedTextField::Name);
    assert_eq!(de.value, "Nummer");
    assert_eq!(de.entity_type, LocalizedTextEntityType::ClaimSchema);
}

#[tokio::test]
async fn test_holder_accept_credential_stores_disclosure_policy() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut credential_schema_importer = MockCredentialSchemaImporter::new();

    let credential = generic_credential_key();

    let disclosure_policy = DisclosurePolicy {
        id: "policy-id".to_string(),
        policy: PolicyType::None,
        description: None,
        url: Some("https://policy.url".to_string()),
    };

    let mock_server_uri = mock_server.uri();
    let interaction_data = HolderInteractionData {
        issuer_url: mock_server_uri.to_owned(),
        credential_endpoint: format!("{mock_server_uri}/credential"),
        token_endpoint: Some(format!("{mock_server_uri}/token")),
        nonce_endpoint: Some(format!("{mock_server_uri}/nonce")),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: "CredentialSchemaId".to_owned(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
        access_certificate: None,
        relying_party_id: None,
        national_registry_url: None,
        registration_certificate: None,
        national_registry_data: None,
        relying_party_name: None,
        trust_resolution: TrustResolutionResult::Unknown,
        trust_mode: TrustMode::Disabled,
        disclosure_policy: Some(disclosure_policy.to_owned()),
    };

    let interaction = Interaction {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: Some(
            credential
                .schema
                .as_ref()
                .unwrap()
                .organisation
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        ),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "nonce"})))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{"credential": "credential"}]
        })))
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(|_, _| Ok(None));

    credential_schema_importer
        .expect_import_credential_schema()
        .once()
        .returning(Ok);

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));
            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));
            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
        )
        .return_once(|_, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockHolderWalletInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut config = dummy_config();
    config.global_settings.default_language = "en".to_string();

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        credential_schema_importer: Some(credential_schema_importer),
        holder_wallet_unit_repository,
        interaction_repository,
        history_repository,
        config,
        ..Default::default()
    });

    // WHEN
    let key = dummy_key();
    let result = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
        )
        .await
        .unwrap();

    // THEN
    let embedded_disclosure_policy: DisclosurePolicy = serde_json::from_str(
        result
            .main_credential
            .credential
            .embedded_disclosure_policy
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(embedded_disclosure_policy, disclosure_policy);
}

fn test_params(issuance_url_scheme: &str) -> serde_json::Value {
    json!({
        "preAuthorizedCodeExpiresIn": 10,
        "tokenExpiresIn": 10,
        "refreshExpiresIn": 1000,
        "credentialOfferByValue": true,
        "encryption": "0000000000000000000000000000000000000000000000000000000000000000",
        "redirectUri": {
            "enabled": true,
            "allowedSchemes": ["https"]
        },
        "urlScheme": issuance_url_scheme,
        "oauthAttestationLeeway": 60,
        "keyAttestationLeeway": 60,
        "trustEcosystemLeeway": 60,
        "requestSignedMetadata": false
    })
}
