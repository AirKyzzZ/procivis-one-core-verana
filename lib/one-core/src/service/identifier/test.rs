use std::collections::HashMap;
use std::sync::Arc;

use dcql::{CredentialFormat, CredentialMeta};
use shared_types::TrustCollectionId;
use similar_asserts::assert_eq;
use url::Url;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionState,
};
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::wrp_validator::MockWRPValidator;
use crate::proto::wrp_validator::model::{AccessCertificateResult, RegistrationCertificateResult};
use crate::provider::blob_storage_provider::{MockBlobStorage, MockBlobStorageProvider};
use crate::provider::signer::registration_certificate::model::{
    Credential, Payload, Status, SupervisoryAuthority, WRPRegistrationCertificatePayload,
};
use crate::provider::trust_list_subscriber::provider::MockTrustListSubscriberProvider;
use crate::provider::trust_list_subscriber::{
    Feature, MockTrustListSubscriber, TrustEntityResponse, TrustListSubscriberCapabilities,
};
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::identifier_trust_information_repository::MockIdentifierTrustInformationRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::identifier::IdentifierService;
use crate::service::identifier::dto::{
    CertificateRolesMatchMode, CreateIdentifierKeyRequestDTO, CreateIdentifierRequestDTO,
    CreateIdentifierTrustInformationRequestDTO, IdentifierFilterParamsDTO,
    IdentifierTrustInformationType, ResolveTrustEntriesRequestDTO,
};
use crate::service::test_utilities::{
    dummy_certificate, dummy_identifier, dummy_key, dummy_organisation, generic_config,
    get_dummy_date,
};

#[derive(Default)]
struct Mocks {
    identifier_repository: MockIdentifierRepository,
    key_repository: MockKeyRepository,
    organisation_repository: MockOrganisationRepository,
    credential_schema_repository: MockCredentialSchemaRepository,
    proof_schema_repository: MockProofSchemaRepository,
    trust_collection_repository: MockTrustCollectionRepository,
    trust_list_subscription_repository: MockTrustListSubscriptionRepository,
    identifier_creator: MockIdentifierCreator,
    session_provider: StaticSessionProvider,
    trust_list_subscriber_provider: MockTrustListSubscriberProvider,
    identifier_trust_information_repository: MockIdentifierTrustInformationRepository,
    blob_storage_provider: MockBlobStorageProvider,
    wrp_validator: MockWRPValidator,
}

fn setup_service(mocks: Mocks) -> IdentifierService {
    IdentifierService {
        identifier_repository: Arc::new(mocks.identifier_repository),
        key_repository: Arc::new(mocks.key_repository),
        organisation_repository: Arc::new(mocks.organisation_repository),
        credential_schema_repository: Arc::new(mocks.credential_schema_repository),
        proof_schema_repository: Arc::new(mocks.proof_schema_repository),
        trust_collection_repository: Arc::new(mocks.trust_collection_repository),
        trust_list_subscription_repository: Arc::new(mocks.trust_list_subscription_repository),
        identifier_trust_information_repository: Arc::new(
            mocks.identifier_trust_information_repository,
        ),
        blob_storage_provider: Arc::new(mocks.blob_storage_provider),
        config: Arc::new(generic_config().core),
        identifier_creator: Arc::new(mocks.identifier_creator),
        session_provider: Arc::new(mocks.session_provider),
        trust_list_subscriber_provider: Arc::new(mocks.trust_list_subscriber_provider),
        transaction_manager: Arc::new(NoTransactionManager),
        wrp_validator: Arc::new(mocks.wrp_validator),
    }
}

fn setup_service_simple(identifier: Option<Identifier>) -> IdentifierService {
    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .returning(move |_, _| Ok(identifier.clone()));

    setup_service(Mocks {
        identifier_repository,
        ..Default::default()
    })
}

fn dummy_trust_list_subscription(
    trust_collection_id: TrustCollectionId,
) -> (TrustListSubscription, TrustCollection) {
    let now = get_dummy_date();
    let organisation_id = Uuid::new_v4().into();
    let trust_collection = TrustCollection {
        id: trust_collection_id,
        name: "test trust collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id,
        organisation: None,
    };
    (
        TrustListSubscription {
            id: Uuid::new_v4().into(),
            name: "test trust list subscription".to_string(),
            created_date: now,
            last_modified: now,
            deactivated_at: None,
            r#type: "test type".to_string().into(),
            reference: "http://test.com".to_string(),
            role: TrustListRoleEnum::Issuer,
            state: TrustListSubscriptionState::Active,
            trust_collection_id,
            trust_collection: Some(trust_collection.clone()),
        },
        trust_collection,
    )
}

#[tokio::test]
async fn test_get_identifier_list_session_org_mismatch() {
    let service = setup_service_simple(None);

    let result = service
        .get_identifier_list(ListQueryDTO {
            page: 0,
            page_size: 0,
            sort: None,
            sort_direction: None,
            filter: IdentifierFilterParamsDTO {
                ids: None,
                name: None,
                types: None,
                states: None,
                did_methods: None,
                is_remote: None,
                key_algorithms: None,
                key_roles: None,
                key_storages: None,
                certificate_roles: None,
                certificate_roles_match_mode: CertificateRolesMatchMode::default(),
                trust_issuance_schema_id: None,
                trust_verification_schema_id: None,
                exact: None,
                organisation_id: Uuid::new_v4().into(),
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
            },
            include: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_create_identifier_session_org_mismatch() {
    let service = setup_service_simple(None);

    let result = service
        .create_identifier(CreateIdentifierRequestDTO {
            name: "".to_string(),
            did: None,
            key: None,
            key_id: None,
            certificates: None,
            certificate_authorities: None,
            organisation_id: Uuid::new_v4().into(),
            trust_information: vec![],
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_identifier_ops_session_org_mismatch() {
    let mut identifier = dummy_identifier();
    identifier.organisation = Some(dummy_organisation(None));
    let service = setup_service_simple(Some(identifier));

    let result = service.get_identifier(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service.delete_identifier(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_resolve_trust_entries_success() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.r#type = IdentifierType::Certificate;

    identifier_repository
        .expect_get()
        .returning(move |_, _| Ok(Some(identifier.clone())));

    let trust_collection_id = Uuid::new_v4().into();
    let (subscription, trust_collection) = dummy_trust_list_subscription(trust_collection_id);

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![subscription.clone()],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![trust_collection.clone()],
                total_items: 1,
                total_pages: 1,
            })
        });

    let mut trust_list_subscriber = MockTrustListSubscriber::default();
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });
    trust_list_subscriber
        .expect_resolve_entries()
        .returning(move |_, _| {
            let mut map = HashMap::new();
            map.insert(identifier_id, TrustEntityResponse::LOTE(Default::default()));
            Ok(map)
        });

    let subscriber_arc: Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber> =
        Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Some(subscriber_arc.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        trust_list_subscriber_provider,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].identifier.id, identifier_id);
    assert_eq!(result[0].trust_entries.len(), 1);
}

#[tokio::test]
async fn test_resolve_trust_entries_filters_local() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.is_remote = false; // Local
    identifier.r#type = IdentifierType::Certificate;

    identifier_repository
        .expect_get()
        .returning(move |_, _| Ok(Some(identifier.clone())));

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
            })
        });

    let mut trust_list_subscriber = MockTrustListSubscriber::default();
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });
    // Should be called with empty identifiers list
    trust_list_subscriber
        .expect_resolve_entries()
        .withf(|_, identifiers| identifiers.is_empty())
        .returning(move |_, _| Ok(HashMap::new()));

    let subscriber_arc: Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber> =
        Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Some(subscriber_arc.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        trust_list_subscriber_provider,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].identifier.id, identifier_id);
    assert_eq!(result[0].trust_entries.len(), 0);
}

#[tokio::test]
async fn test_resolve_trust_entries_ignores_missing_identifiers() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();

    let identifier_id = Uuid::new_v4().into();
    identifier_repository
        .expect_get()
        .returning(move |_, _| Ok(None));

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
            })
        });

    let service = setup_service(Mocks {
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    // Result should be empty because the identifier was not found in repo
    assert_eq!(result.len(), 0);
}

#[tokio::test]
async fn test_resolve_trust_entries_subscriber_error() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.r#type = IdentifierType::Certificate;

    identifier_repository
        .expect_get()
        .returning(move |_, _| Ok(Some(identifier.clone())));

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
            })
        });

    let mut trust_list_subscriber = MockTrustListSubscriber::default();
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });
    trust_list_subscriber
        .expect_resolve_entries()
        .returning(move |_, _| Err(crate::provider::trust_list_subscriber::error::TrustListSubscriberError::MappingError("error".to_string())));

    let subscriber_arc: Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber> =
        Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Some(subscriber_arc.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        trust_list_subscriber_provider,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await;

    // then
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0047);
}

#[tokio::test]
async fn test_resolve_trust_entries_filters_key_type() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.r#type = IdentifierType::Key;

    identifier_repository
        .expect_get()
        .returning(move |_, _| Ok(Some(identifier.clone())));

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
            })
        });

    let mut trust_list_subscriber = MockTrustListSubscriber::default();
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });

    // Should be called with empty identifiers list because Key type is filtered out
    trust_list_subscriber
        .expect_resolve_entries()
        .withf(|_, identifiers| identifiers.is_empty())
        .returning(move |_, _| Ok(HashMap::new()));

    let subscriber_arc: Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber> =
        Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Some(subscriber_arc.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        trust_list_subscriber_provider,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].identifier.id, identifier_id);
    assert_eq!(result[0].trust_entries.len(), 0);
}

#[tokio::test]
async fn test_create_identifier_with_trust_information() {
    let session_provider = StaticSessionProvider::new_random();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut key_repository = MockKeyRepository::default();
    let dummy_key = dummy_key();
    let key_id = dummy_key.id;
    key_repository
        .expect_get_key()
        .returning(move |_, _| Ok(Some(dummy_key.clone())));
    let mut identifier_creator = MockIdentifierCreator::default();
    let mut identifier_trust_information_repository =
        MockIdentifierTrustInformationRepository::default();
    identifier_trust_information_repository
        .expect_create()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));
    let mut blob_storage = MockBlobStorage::default();
    blob_storage.expect_create().once().returning(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Some(blob_storage.clone()));

    let organisation_id = session_provider.0.organisation_id.unwrap();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_, _| Ok(Some(dummy_organisation(Some(organisation_id)))));

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.certificates = Some(vec![dummy_certificate(identifier_id)]);
    identifier.id = identifier_id;
    identifier.organisation = Some(dummy_organisation(Some(organisation_id)));

    identifier_creator
        .expect_create_local_identifier()
        .returning(move |_, _, _| Ok(identifier.clone()));
    let mut wrp_validator = MockWRPValidator::new();
    wrp_validator
        .expect_validate_access_certificate_trust()
        .once()
        .returning(|_, _| {
            Ok(AccessCertificateResult {
                trust_entity: None,
                relying_party_id: "test_wrp".to_string(),
                registry_url: None,
            })
        });
    wrp_validator
        .expect_validate_registration_certificate()
        .once()
        .returning(|_, rp_id, _, _| {
            assert_eq!(rp_id, "test_wrp");
            Ok(RegistrationCertificateResult {
                trust_entity: None,
                payload: dummy_reg_cert(),
            })
        });

    let service = setup_service(Mocks {
        organisation_repository,
        key_repository,
        identifier_creator,
        identifier_trust_information_repository,
        blob_storage_provider,
        session_provider,
        wrp_validator,
        ..Default::default()
    });

    let result = service
        .create_identifier(CreateIdentifierRequestDTO {
            name: "test identifier".to_string(),
            did: None,
            key: Some(CreateIdentifierKeyRequestDTO { key_id }),
            key_id: None,
            certificates: None,
            certificate_authorities: None,
            organisation_id,
            trust_information: vec![CreateIdentifierTrustInformationRequestDTO {
                data: "dummy reg cert".to_string(),
                r#type: IdentifierTrustInformationType::RegistrationCertificate,
            }],
        })
        .await;
    assert!(result.is_ok());
}

fn dummy_reg_cert() -> JWTPayload<Payload> {
    WRPRegistrationCertificatePayload {
        issued_at: None,
        expires_at: None,
        invalid_before: None,
        issuer: None,
        subject: Some("subject".to_string()),
        audience: None,
        jwt_id: None,
        proof_of_possession_key: None,
        custom: Payload {
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
            provides_attestations: Some(vec![Credential {
                format: CredentialFormat::SdJwt,
                meta: CredentialMeta::SdJwtVc {
                    vct_values: vec!["https://example.com".to_string()],
                },
                claim: None,
            }]),
            credentials: Some(vec![Credential {
                format: CredentialFormat::SdJwt,
                meta: CredentialMeta::SdJwtVc {
                    vct_values: vec!["https://example2.com".to_string()],
                },
                claim: None,
            }]),
            purpose: None,
            intended_use_id: Some("intended_use_id".to_string()),
            public_body: None,
            support_uri: Url::parse("https://example.com").unwrap(),
            intermediary: None,
        },
    }
}
