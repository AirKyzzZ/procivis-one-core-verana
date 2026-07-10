use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use dcql::{CredentialQueryId, DcqlQuery};
use indexmap::IndexMap;
use mockall::predicate::{always, eq};
use serde_json::json;
use shared_types::{CredentialFormat, TransactionDataId};
use similar_asserts::assert_eq;
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};
use standardized_types::openid4vp::{ClientMetadata, MdocAlgs, PresentationFormat, ResponseMode};
use url::Url;
use uuid::Uuid;

use super::OpenID4VPFinal1_0;
use crate::config::core_config::FormatType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::holder_trust_resolver::MockHolderTrustResolver;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::trust_information::MockTrustInformationProvider;
use crate::proto::wrp_validator::MockWRPValidator;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyAgreementHandle, KeyHandle, MockPublicKeyAgreementHandle, MockSignaturePublicKeyHandle,
    SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::KeyStorageCapabilities;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::transaction_data::provider::MockTransactionDataProvider;
use crate::provider::verification_protocol::dto::{FormattedCredentialPresentation, ShareResponse};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, HolderTxData, OpenID4VPHolderInteractionData, ValidatedHolderTxData,
};
use crate::provider::verification_protocol::{
    FormatMapper, VerificationProtocol, serialize_interaction_data,
};
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::service::test_utilities::{
    dummy_claim_schema, dummy_credential_schema, dummy_dcql_query, dummy_identifier,
    dummy_organisation, generic_config,
};

#[derive(Default)]
struct TestInputs {
    pub credential_formatter_provider: MockCredentialFormatterProvider,
    pub presentation_formatter_provider: MockPresentationFormatterProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub certificate_validator: MockCertificateValidator,
    pub http_client: MockHttpClient,
    pub interaction_repository: MockInteractionRepository,
    pub wrp_validator: MockWRPValidator,
    pub trust_information_provider: MockTrustInformationProvider,
    pub transaction_data_provider: MockTransactionDataProvider,
    pub holder_trust_resolver: MockHolderTrustResolver,
    pub params: Option<serde_json::Value>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VPFinal1_0 {
    OpenID4VPFinal1_0::new(
        "final1".to_string(),
        Some("http://base_url".to_string()),
        Arc::new(inputs.credential_formatter_provider),
        Arc::new(inputs.presentation_formatter_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.certificate_validator),
        Arc::new(MockCredentialRepository::default()),
        Arc::new(MockCredentialSchemaRepository::default()),
        Arc::new(inputs.interaction_repository),
        Arc::new(inputs.wrp_validator),
        Arc::new(inputs.trust_information_provider),
        Arc::new(inputs.transaction_data_provider),
        Arc::new(inputs.holder_trust_resolver),
        Arc::new(inputs.http_client),
        inputs.params.unwrap_or(generic_params()),
        Arc::new(generic_config().core),
    )
    .unwrap()
}

fn generic_params() -> serde_json::Value {
    json!({
        "allowInsecureHttpTransport": true,
        "useRequestUri": false,
        "urlScheme": "openid4vp",
        "holder":  {
            "supportedClientIdSchemes": [
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation
            ],
            "trustEcosystemsLeeway": 45
        },
        "verifier": {
            "interactionExpiresIn": 1000,
            "supportedClientIdSchemes": [
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation
            ],
        },
        "redirectUri": {
            "enabled": true,
            "allowedSchemes": ["https"],
        }
    })
}

fn test_credential_schema(format: CredentialFormat) -> CredentialSchema {
    CredentialSchema {
        formats: vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_id: Uuid::new_v4().into(),
            format,
            schema_id: "test_schema_id".to_owned(),
            claim_mappings: Default::default(),
        }]
        .into(),
        batch_size: None,
        name: "test-credential-schema".to_string(),
        imported_source_url: "test_imported_src_url".to_string(),
        ..dummy_credential_schema()
    }
}

fn test_key(key_type: &str) -> Key {
    Key {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        public_key: vec![],
        name: "test_key".to_string(),
        key_reference: None,
        storage_type: "INTERNAL".to_string(),
        key_type: key_type.to_string(),
        organisation: dummy_organisation(None).into(),
    }
}

fn test_verifier_proof(format: CredentialFormat, verifier_key: Option<RelatedKey>) -> Proof {
    let key = verifier_key
        .clone()
        .map(|k| k.key)
        .unwrap_or_else(|| test_key("ECDSA"));

    Proof {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "OPENID4VP_FINAL1".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            deleted_at: None,
            name: "test-share-proof".into(),
            expire_duration: 123,
            imported_source_url: None,
            organisation: None,
            input_schemas: Some(vec![ProofInputSchema {
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "required_key".to_string(),
                        ..dummy_claim_schema()
                    },
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(test_credential_schema(format)),
            }]),
        }),
        claims: None,
        verifier_identifier: Some(Identifier {
            did: Some(
                (Did {
                    deleted_at: None,
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    name: "did".to_string(),
                    did: "did:example:123".parse().unwrap(),
                    did_type: DidType::Local,
                    did_method: "KEY".into(),
                    deactivated: false,
                    keys: verifier_key
                        .map(|k| vec![k])
                        .unwrap_or(vec![RelatedKey {
                            role: KeyRole::AssertionMethod,
                            key: key.clone(),
                            reference: "1".to_string(),
                        }])
                        .into(),
                    organisation: dummy_organisation(None).into(),
                    log: None,
                })
                .into(),
            ),
            ..dummy_identifier()
        }),
        verifier_key: Some(key),
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
    }
}

fn test_holder_interaction_data(
    response_mode: Option<ResponseMode>,
) -> OpenID4VPHolderInteractionData {
    OpenID4VPHolderInteractionData {
        response_type: Some("vp_token".to_string()),
        state: Some(Uuid::new_v4().to_string()),
        nonce: Some("test-nonce-12345".to_string()),
        client_id_scheme: ClientIdScheme::RedirectUri,
        client_id: "https://verifier.example.com".to_string(),
        client_metadata: Some(ClientMetadata {
            vp_formats_supported: HashMap::from([(
                "mso_mdoc".to_string(),
                PresentationFormat::MdocAlgs(MdocAlgs {
                    issuerauth_alg_values: vec![],
                    deviceauth_alg_values: vec![],
                }),
            )]),
            ..Default::default()
        }),
        client_metadata_uri: None,
        response_mode,
        response_uri: Some("https://verifier.example.com/response".parse().unwrap()),
        dcql_query: dummy_dcql_query(true),
        transaction_data: Default::default(),
        redirect_uri: None,
        verifier_details: None,
        verifier_info: vec![],
    }
}

fn test_holder_proof(
    interaction_data: OpenID4VPHolderInteractionData,
    format: CredentialFormat,
) -> Proof {
    let interaction = Interaction {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        data: Some(serialize_interaction_data(&interaction_data).unwrap()),
        organisation: dummy_organisation(None).into(),
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    };

    Proof {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "OPENID4VP_FINAL1".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Requested,
        role: ProofRole::Holder,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            deleted_at: None,
            name: "test-holder-proof".into(),
            expire_duration: 300,
            imported_source_url: None,
            organisation: None,
            input_schemas: Some(vec![ProofInputSchema {
                claim_schemas: None,
                credential_schema: Some(test_credential_schema(format)),
            }]),
        }),
        claims: None,
        verifier_identifier: None,
        verifier_key: Some(test_key("ECDSA")),
        verifier_certificate: None,
        interaction: Some(interaction),
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
    }
}

fn mock_http_post(url: &str) -> MockHttpClient {
    let url = url.to_string();
    let mut mock_client = MockHttpClient::new();

    let url_for_eq = url.clone();
    mock_client
        .expect_post()
        .with(eq(url_for_eq))
        .returning(move |req_url| {
            let mut inner_client = MockHttpClient::new();
            let url_for_response = url.clone();
            inner_client
                .expect_send()
                .with(
                    eq(url.clone()),
                    always(),
                    always(),
                    eq(Method::Post),
                    always(),
                )
                .return_once(move |_, _, _, _, _| {
                    Ok(Response {
                        body: b"{}".to_vec(),
                        headers: Default::default(),
                        status: StatusCode(200),
                        request: Request {
                            body: None,
                            headers: Default::default(),
                            method: Method::Post,
                            url: url_for_response,
                            timeout: None,
                        },
                    })
                });
            RequestBuilder::new(Arc::new(inner_client), Method::Post, req_url)
        });

    mock_client
}

fn setup_key_agreement_mocks(
    crv: &'static str,
    _key_type: &'static str,
    jwk_constructor: impl FnOnce(PublicJwkEc) -> PublicJwk + Send + 'static,
) -> (MockKeyAlgorithmProvider, MockKeyProvider, Uuid) {
    let key_id = Uuid::new_v4();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_get_capabilities()
        .returning(KeyStorageCapabilities::default);

    let mut key_provider = MockKeyProvider::new();
    let arc = Arc::new(key_storage);
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Ok(arc.clone()));

    let mut key_algorithm = MockKeyAlgorithm::new();
    key_algorithm
        .expect_reconstruct_key()
        .return_once(move |_, _, _| {
            let mut key_agreement_handle = MockPublicKeyAgreementHandle::default();
            key_agreement_handle.expect_as_jwk().return_once(move || {
                Ok(jwk_constructor(PublicJwkEc {
                    alg: None,
                    r#use: Some(JwkUse::Encryption),
                    kid: None,
                    crv: crv.to_string(),
                    x: "".to_string(),
                    y: Some("".to_string()),
                }))
            });
            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    MockSignaturePublicKeyHandle::default(),
                )),
                key_agreement: KeyAgreementHandle::PublicKeyOnly(Arc::new(key_agreement_handle)),
            })
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let arc = Arc::new(key_algorithm);
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .returning(move |_| Ok(arc.clone()));

    (key_algorithm_provider, key_provider, key_id)
}

#[tokio::test]
async fn test_share_proof_direct_post() {
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_user_claims_path()
        .returning(Vec::new);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| Ok(Arc::new(credential_formatter)));

    let protocol = setup_protocol(TestInputs {
        credential_formatter_provider: formatter_provider,
        ..Default::default()
    });

    let proof = test_verifier_proof("JWT".into(), None);
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let ShareResponse {
        url,
        interaction_id,
        ..
    } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();

    let url: Url = url.parse().unwrap();
    let query_pairs: HashMap<Cow<'_, str>, Cow<'_, str>> = url.query_pairs().collect();

    let expected_keys = vec![
        "client_id",
        "client_metadata",
        "dcql_query",
        "nonce",
        "response_mode",
        "response_type",
        "response_uri",
        "state",
    ];

    let mut actual_keys: Vec<&str> = query_pairs.keys().map(|k| k.as_ref()).collect();
    actual_keys.sort();
    assert_eq!(expected_keys, actual_keys);

    assert_eq!("vp_token", query_pairs.get("response_type").unwrap());
    assert_eq!("direct_post", query_pairs.get("response_mode").unwrap());
    assert_eq!(
        &interaction_id.to_string(),
        query_pairs.get("state").unwrap()
    );
    assert_eq!(
        "http://base_url/ssi/openid4vp/final-1.0/response",
        query_pairs.get("response_uri").unwrap()
    );
    assert_eq!(
        "redirect_uri:http://base_url/ssi/openid4vp/final-1.0/response",
        query_pairs.get("client_id").unwrap()
    );

    let returned_dcql_query =
        serde_json::from_str::<DcqlQuery>(query_pairs.get("dcql_query").unwrap()).unwrap();
    let returned_client_metadata =
        serde_json::from_str::<ClientMetadata>(query_pairs.get("client_metadata").unwrap())
            .unwrap();

    assert_eq!(returned_client_metadata.jwks, None);
    assert_eq!(
        returned_client_metadata.encrypted_response_enc_values_supported,
        None
    );
    assert_eq!(returned_dcql_query.credentials.len(), 1);
}

#[tokio::test]
async fn test_share_proof_direct_post_jwt_ecdsa() {
    let (key_algorithm_provider, key_provider, key_id) =
        setup_key_agreement_mocks("P-256", "ECDSA", PublicJwk::Ec);

    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_user_claims_path()
        .returning(Vec::new);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| Ok(Arc::new(credential_formatter)));

    let protocol = setup_protocol(TestInputs {
        key_provider,
        key_algorithm_provider,
        credential_formatter_provider: formatter_provider,
        ..Default::default()
    });

    let key_agreement_key = RelatedKey {
        role: KeyRole::KeyAgreement,
        key: Key {
            id: key_id.into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            public_key: vec![],
            name: "key".to_string(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: "ECDSA".to_string(),
            organisation: dummy_organisation(None).into(),
        },
        reference: "1".to_string(),
    };

    let proof = test_verifier_proof("JWT".into(), Some(key_agreement_key));
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();

    let url: Url = url.parse().unwrap();
    let query_pairs: HashMap<Cow<'_, str>, Cow<'_, str>> = url.query_pairs().collect();

    assert_eq!("direct_post.jwt", query_pairs.get("response_mode").unwrap());

    let returned_client_metadata =
        serde_json::from_str::<ClientMetadata>(query_pairs.get("client_metadata").unwrap())
            .unwrap();

    let jwks = returned_client_metadata.jwks.unwrap().keys;
    assert_eq!(jwks.len(), 1);
    assert_eq!(jwks[0].r#use(), Some(&JwkUse::Encryption));
    assert_eq!(jwks[0].kid().unwrap(), key_id.to_string().as_str());

    assert_eq!(
        returned_client_metadata.encrypted_response_enc_values_supported,
        Some(vec![
            EncryptionAlgorithm::A128GCM,
            EncryptionAlgorithm::A256GCM,
            EncryptionAlgorithm::A128CBCHS256,
        ])
    );
}

#[tokio::test]
async fn test_share_proof_direct_post_jwt_eddsa() {
    let (key_algorithm_provider, key_provider, key_id) =
        setup_key_agreement_mocks("Ed25519", "EDDSA", |data| {
            PublicJwk::Okp(PublicJwkEc { y: None, ..data })
        });

    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_user_claims_path()
        .returning(Vec::new);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| Ok(Arc::new(credential_formatter)));

    let protocol = setup_protocol(TestInputs {
        key_provider,
        key_algorithm_provider,
        credential_formatter_provider: formatter_provider,
        ..Default::default()
    });

    let key_agreement_key = RelatedKey {
        role: KeyRole::KeyAgreement,
        key: Key {
            id: key_id.into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            public_key: vec![],
            name: "key".to_string(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: "EDDSA".to_string(),
            organisation: dummy_organisation(None).into(),
        },
        reference: "1".to_string(),
    };

    let proof = test_verifier_proof("JWT".into(), Some(key_agreement_key));
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();

    let url: Url = url.parse().unwrap();
    let query_pairs: HashMap<Cow<'_, str>, Cow<'_, str>> = url.query_pairs().collect();

    assert_eq!("direct_post.jwt", query_pairs.get("response_mode").unwrap());

    let returned_client_metadata =
        serde_json::from_str::<ClientMetadata>(query_pairs.get("client_metadata").unwrap())
            .unwrap();

    let jwks = returned_client_metadata.jwks.unwrap().keys;
    assert_eq!(jwks.len(), 1);
    assert_eq!(jwks[0].r#use(), Some(&JwkUse::Encryption));
    assert_eq!(jwks[0].kid().unwrap(), key_id.to_string());
}

#[tokio::test]
async fn test_holder_submit_missing_response_mode_fails() {
    let protocol = setup_protocol(TestInputs::default());
    let proof = test_holder_proof(test_holder_interaction_data(None), "MDOC".into());

    let result = protocol.holder_submit_proof(&proof, vec![]).await;

    assert!(
        matches!(&result, Err(VerificationProtocolError::InvalidRequest(_))),
        "Expected InvalidRequest error for missing response_mode, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_holder_submit_direct_post_jwt_no_encryption_keys_fails() {
    let protocol = setup_protocol(TestInputs::default());
    let proof = test_holder_proof(
        test_holder_interaction_data(Some(ResponseMode::DirectPostJwt)),
        "MDOC".into(),
    );

    let result = protocol.holder_submit_proof(&proof, vec![]).await;

    assert!(
        matches!(&result, Err(VerificationProtocolError::InvalidRequest(_))),
        "Expected InvalidRequest error when direct_post.jwt has no encryption keys, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_holder_submit_mdoc_direct_post() {
    let protocol = setup_protocol(TestInputs {
        http_client: mock_http_post("https://verifier.example.com/response"),
        ..Default::default()
    });

    let proof = test_holder_proof(
        test_holder_interaction_data(Some(ResponseMode::DirectPost)),
        "MDOC".into(),
    );

    // Verifies: response_mode validation passes, no MDOC-requires-encryption error, HTTP POST succeeds
    let result = protocol.holder_submit_proof(&proof, vec![]).await;
    assert!(result.is_ok(), "Expected Ok but got: {:?}", result);
}

fn interaction_with_validated_tx_data(
    entries: Vec<(TransactionDataId, &str, Vec<&str>)>,
) -> OpenID4VPHolderInteractionData {
    let mut data = test_holder_interaction_data(Some(ResponseMode::DirectPost));
    let mut map = IndexMap::new();
    for (id, raw, credential_query_ids) in entries {
        map.insert(
            id,
            ValidatedHolderTxData {
                raw: raw.to_string(),
                credential_query_ids: credential_query_ids
                    .into_iter()
                    .map(CredentialQueryId::from)
                    .collect(),
                transaction_data_type: "QES_APPROVAL".into(),
            },
        );
    }
    data.transaction_data = HolderTxData::Validated(map);
    data
}

fn test_credential_presentation(
    credential_query_id: &str,
    transaction_data_ids: Vec<TransactionDataId>,
) -> FormattedCredentialPresentation {
    FormattedCredentialPresentation {
        presentation: "presentation-token".to_string(),
        credential_schema: test_credential_schema("MDOC".into()),
        credential_query_id: CredentialQueryId::from(credential_query_id),
        holder_did: None,
        key: test_key("ECDSA"),
        jwk_key_id: None,
        transaction_data_ids,
    }
}

#[tokio::test]
async fn test_holder_submit_transaction_data_unknown_selection_fails() {
    let protocol = setup_protocol(TestInputs::default());

    let tx_id = TransactionDataId::from(Uuid::new_v4());
    let interaction = interaction_with_validated_tx_data(vec![(tx_id, "raw-tx", vec!["cred1"])]);
    let proof = test_holder_proof(interaction, "MDOC".into());

    // Select a transaction data id that does not exist in the interaction data.
    let presentation =
        test_credential_presentation("cred1", vec![TransactionDataId::from(Uuid::new_v4())]);

    let result = protocol
        .holder_submit_proof(&proof, vec![presentation])
        .await;

    assert!(matches!(
        &result,
        Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            _
        ))
    ));
}

#[tokio::test]
async fn test_holder_submit_transaction_data_non_applicable_selection_fails() {
    let protocol = setup_protocol(TestInputs::default());

    // Transaction data applies only to `cred2`.
    let tx_id = TransactionDataId::from(Uuid::new_v4());
    let interaction = interaction_with_validated_tx_data(vec![(tx_id, "raw-tx", vec!["cred2"])]);
    let proof = test_holder_proof(interaction, "MDOC".into());

    // `cred1` selects it even though it is not applicable to `cred1`.
    let presentation = test_credential_presentation("cred1", vec![tx_id]);

    let result = protocol
        .holder_submit_proof(&proof, vec![presentation])
        .await;

    assert!(matches!(
        &result,
        Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            _
        ))
    ));
}

#[tokio::test]
async fn test_holder_submit_transaction_data_duplicate_selection_fails() {
    let protocol = setup_protocol(TestInputs::default());

    let tx_id = TransactionDataId::from(Uuid::new_v4());
    let interaction = interaction_with_validated_tx_data(vec![(tx_id, "raw-tx", vec!["cred1"])]);
    let proof = test_holder_proof(interaction, "MDOC".into());

    // The same transaction data id is selected twice.
    let presentation = test_credential_presentation("cred1", vec![tx_id, tx_id]);

    let result = protocol
        .holder_submit_proof(&proof, vec![presentation])
        .await;

    assert!(matches!(
        &result,
        Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            _
        ))
    ));
}
