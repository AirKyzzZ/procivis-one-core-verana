use std::str::FromStr;
use std::sync::Arc;

use one_core::model::certificate::{
    Certificate, CertificateRelations, CertificateRole, CertificateState,
};
use one_core::model::common::SortDirection;
use one_core::model::did::Did;
use one_core::model::identifier::{
    Identifier, IdentifierFilterValue, IdentifierListQuery, IdentifierRelations, IdentifierState,
    IdentifierType, SortableIdentifierColumn,
};
use one_core::model::identifier_trust_information::{
    IdentifierTrustInformation, IdentifierTrustInformationRelations, SchemaFormat,
};
use one_core::model::list_filter::{ListFilterCondition, ListFilterValue};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::organisation::Organisation;
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::did_repository::MockDidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use one_core::repository::key_repository::MockKeyRepository;
use sea_orm::DatabaseConnection;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::IdentifierProvider;
use crate::entity::blob::BlobType;
use crate::test_utilities::{
    dummy_organisation, get_dummy_date, insert_blob_to_database, insert_did_key,
    insert_organisation_to_database, setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: IdentifierProvider,
    pub organisation: Organisation,
    pub did: Did,
    pub db: DatabaseConnection,
    pub certificate_repository: Arc<dyn CertificateRepository>,
    pub trust_information_repository: Arc<dyn IdentifierTrustInformationRepository>,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();
    let organisation = dummy_organisation(Some(organisation_id));

    let did_id = insert_did_key(
        &db,
        "test_did",
        Uuid::new_v4(),
        DidValue::from_str("did:test:123").unwrap(),
        "KEY",
        organisation_id,
    )
    .await
    .unwrap();

    let did = Did {
        deleted_at: None,
        id: did_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_did".to_string(),
        did: DidValue::from_str("did:test:123").unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".into(),
        deactivated: false,
        log: None,
        keys: Default::default(),
        organisation: Some(organisation.clone().into()),
    };

    TestSetup {
        provider: IdentifierProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository: data_layer.organisation_repository,
            did_repository: Arc::new(MockDidRepository::default()),
            key_repository: Arc::new(MockKeyRepository::default()),
            certificate_repository: data_layer.certificate_repository.clone(),
            trust_information_repository: data_layer
                .identifier_trust_information_repository
                .clone(),
        },
        organisation,
        did,
        db,
        certificate_repository: data_layer.certificate_repository,
        trust_information_repository: data_layer.identifier_trust_information_repository,
    }
}

#[tokio::test]
async fn test_create_and_delete_identifier() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let identifier = Identifier {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: setup.organisation.into(),
        did: Some(setup.did),
        key: None,
        certificates: None,
        deleted_at: None,
        trust_information: None,
    };

    assert_eq!(id, setup.provider.create(identifier.clone()).await.unwrap());

    setup.provider.delete(&id).await.unwrap();

    assert!(matches!(
        setup.provider.create(identifier).await,
        Err(DataLayerError::AlreadyExists)
    ));
}

#[tokio::test]
async fn test_get_identifier() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let identifier = Identifier {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: setup.organisation.clone().into(),
        did: Some(setup.did.clone()),
        key: None,
        certificates: None,
        deleted_at: None,
        trust_information: None,
    };

    setup.provider.create(identifier.clone()).await.unwrap();

    let non_existent_id = Uuid::new_v4().into();
    assert!(
        setup
            .provider
            .get(non_existent_id, &Default::default())
            .await
            .unwrap()
            .is_none()
    );

    let retrieved = setup
        .provider
        .get(id, &Default::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved.id, identifier.id);
    assert_eq!(retrieved.name, identifier.name);
    assert_eq!(retrieved.r#type, identifier.r#type);
    assert_eq!(retrieved.state, identifier.state);
    assert_eq!(retrieved.is_remote, identifier.is_remote);
    assert_eq!(retrieved.organisation.id(), identifier.organisation.id());
    assert!(retrieved.did.is_none());
    assert!(retrieved.key.is_none());
}

#[tokio::test]
async fn test_get_identifier_list() {
    let setup = setup().await;
    let id1 = Uuid::new_v4().into();
    let id2 = Uuid::new_v4().into();

    let identifier1 = Identifier {
        id: id1,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier1".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: setup.organisation.clone().into(),
        did: Some(setup.did.clone()),
        key: None,
        certificates: None,
        deleted_at: None,
        trust_information: None,
    };

    let did2_id = insert_did_key(
        &setup.db,
        "test_did2",
        Uuid::new_v4(),
        DidValue::from_str("did:test:124").unwrap(),
        "KEY",
        setup.organisation.id,
    )
    .await
    .unwrap();

    let did2 = Did {
        deleted_at: None,
        id: did2_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_did2".to_string(),
        did: DidValue::from_str("did:test:124").unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".into(),
        deactivated: false,
        log: None,
        keys: Default::default(),
        organisation: Some(setup.organisation.clone().into()),
    };

    let identifier2 = Identifier {
        id: id2,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier2".to_string(),
        r#type: IdentifierType::Did,
        is_remote: true,
        state: IdentifierState::Active,
        organisation: setup.organisation.clone().into(),
        did: Some(did2),
        key: None,
        certificates: None,
        deleted_at: None,
        trust_information: None,
    };

    setup.provider.create(identifier1.clone()).await.unwrap();
    setup.provider.create(identifier2.clone()).await.unwrap();

    let query = IdentifierListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableIdentifierColumn::CreatedDate,
            direction: Some(SortDirection::Descending),
        }),
        filtering: Some(ListFilterCondition::Value(
            IdentifierFilterValue::OrganisationId(setup.organisation.id),
        )),
        include: None,
    };

    let result = setup.provider.get_identifier_list(query).await.unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 2);

    let query = IdentifierListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        sorting: Some(ListSorting {
            column: SortableIdentifierColumn::Name,
            direction: Some(SortDirection::Ascending),
        }),
        filtering: Some(ListFilterCondition::Value(IdentifierFilterValue::Types(
            vec![IdentifierType::Did],
        ))),
        include: None,
    };

    let result = setup.provider.get_identifier_list(query).await.unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 2);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, id1);
}

#[tokio::test]
async fn test_get_identifier_with_trust_info() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let identifier = Identifier {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: setup.organisation.clone().into(),
        did: Some(setup.did.clone()),
        key: None,
        certificates: None,
        deleted_at: None,
        trust_information: None,
    };

    setup.provider.create(identifier.clone()).await.unwrap();
    setup
        .trust_information_repository
        .create(IdentifierTrustInformation {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            valid_from: None,
            valid_to: None,
            intended_use: None,
            allowed_issuance_types: vec![],
            allowed_verification_types: vec![
                SchemaFormat {
                    format: "jwt_vc_json".to_string(),
                    schema_id: "test-schema-id".to_string(),
                },
                SchemaFormat {
                    format: "vc+sd-jwt".to_string(),
                    schema_id: "test-schema-id".to_string(),
                },
            ],
            identifier_id: id,
            blob_id: insert_blob_to_database(
                &setup.db,
                None,
                BlobType::RegistrationCertificate,
                None,
            )
            .await
            .unwrap(),
        })
        .await
        .unwrap();
    setup
        .trust_information_repository
        .create(IdentifierTrustInformation {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            valid_from: None,
            valid_to: None,
            intended_use: None,
            allowed_issuance_types: vec![SchemaFormat {
                format: "jwt_vc_json".to_string(),
                schema_id: "test-schema-id".to_string(),
            }],
            allowed_verification_types: vec![],
            identifier_id: id,
            blob_id: insert_blob_to_database(
                &setup.db,
                None,
                BlobType::RegistrationCertificate,
                None,
            )
            .await
            .unwrap(),
        })
        .await
        .unwrap();

    let identifier = setup
        .provider
        .get(
            id,
            &IdentifierRelations {
                trust_information: Some(IdentifierTrustInformationRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert!(identifier.trust_information.is_some());
    assert_eq!(identifier.trust_information.unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_identifier_filter_trust_info() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let identifier = Identifier {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: setup.organisation.clone().into(),
        did: Some(setup.did.clone()),
        key: None,
        certificates: None,
        deleted_at: None,
        trust_information: None,
    };
    setup.provider.create(identifier.clone()).await.unwrap();

    let schema_format1 = SchemaFormat {
        format: "jwt_vc_json".to_string(),
        schema_id: "test-schema-id".to_string(),
    };
    let schema_format2 = SchemaFormat {
        format: "vc+sd-jwt".to_string(),
        schema_id: "test-schema-id".to_string(),
    };
    let schema_format3 = SchemaFormat {
        format: "vc+sd-jwt".to_string(),
        schema_id: "test-schema-id3".to_string(),
    };
    setup
        .trust_information_repository
        .create(IdentifierTrustInformation {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            valid_from: None,
            valid_to: None,
            intended_use: None,
            allowed_issuance_types: vec![],
            allowed_verification_types: vec![schema_format1.clone(), schema_format2.clone()],
            identifier_id: id,
            blob_id: insert_blob_to_database(
                &setup.db,
                None,
                BlobType::RegistrationCertificate,
                None,
            )
            .await
            .unwrap(),
        })
        .await
        .unwrap();
    setup
        .trust_information_repository
        .create(IdentifierTrustInformation {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            valid_from: None,
            valid_to: None,
            intended_use: None,
            allowed_issuance_types: vec![schema_format1.clone()],
            allowed_verification_types: vec![],
            identifier_id: id,
            blob_id: insert_blob_to_database(
                &setup.db,
                None,
                BlobType::RegistrationCertificate,
                None,
            )
            .await
            .unwrap(),
        })
        .await
        .unwrap();

    let list = setup
        .provider
        .get_identifier_list(IdentifierListQuery {
            filtering: Some(
                IdentifierFilterValue::TrustAllowedIssuanceTypes(schema_format1.clone())
                    .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(list.total_items, 1);

    let list = setup
        .provider
        .get_identifier_list(IdentifierListQuery {
            filtering: Some(
                IdentifierFilterValue::TrustAllowedVerificationTypes(schema_format2.clone())
                    .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(list.total_items, 1);

    let list = setup
        .provider
        .get_identifier_list(IdentifierListQuery {
            filtering: Some(
                IdentifierFilterValue::TrustAllowedVerificationTypes(schema_format1).condition()
                    & IdentifierFilterValue::TrustAllowedVerificationTypes(schema_format2),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(list.total_items, 1);

    let list = setup
        .provider
        .get_identifier_list(IdentifierListQuery {
            filtering: Some(
                IdentifierFilterValue::TrustAllowedVerificationTypes(schema_format3).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(list.total_items, 0);
}

#[tokio::test]
async fn test_list_identifier_filter_certificate_role() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let identifier = Identifier {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier".to_string(),
        r#type: IdentifierType::Certificate,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: setup.organisation.clone().into(),
        did: Some(setup.did.clone()),
        key: None,
        certificates: None,
        deleted_at: None,
        trust_information: None,
    };
    setup.provider.create(identifier.clone()).await.unwrap();

    setup
        .certificate_repository
        .create(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id: id,
            organisation: Some(setup.organisation.into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            expiry_date: get_dummy_date(),
            name: "".to_string(),
            chain: "".to_string(),
            fingerprint: "".to_string(),
            state: CertificateState::Active,
            roles: vec![CertificateRole::Authentication],
            key: None,
        })
        .await
        .unwrap();

    let list = setup
        .provider
        .get_identifier_list(IdentifierListQuery {
            filtering: Some(
                IdentifierFilterValue::CertificateRole(CertificateRole::Authentication).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(list.total_items, 1);

    let list = setup
        .provider
        .get_identifier_list(IdentifierListQuery {
            filtering: Some(
                IdentifierFilterValue::CertificateRole(CertificateRole::AssertionMethod)
                    .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(list.total_items, 0);
}

#[tokio::test]
async fn test_get_returns_soft_deleted_certificates_in_relation() {
    let setup = setup().await;
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let identifier = Identifier {
        id: identifier_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "cert_identifier".to_string(),
        r#type: IdentifierType::Certificate,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: setup.organisation.clone().into(),
        did: None,
        key: None,
        certificates: None,
        deleted_at: None,
        trust_information: None,
    };
    setup.provider.create(identifier.clone()).await.unwrap();

    let cert_id: shared_types::CertificateId = Uuid::new_v4().into();
    let certificate = Certificate {
        id: cert_id,
        identifier_id,
        organisation: Some(setup.organisation.into()),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        deleted_at: None,
        expiry_date: get_dummy_date(),
        name: "cert".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fp-resolve-soft-deleted".to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
    };
    setup
        .certificate_repository
        .create(certificate.clone())
        .await
        .unwrap();

    setup
        .certificate_repository
        .delete(&certificate)
        .await
        .unwrap();

    let resolved = setup
        .provider
        .get(
            identifier_id,
            &IdentifierRelations {
                certificates: Some(CertificateRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .expect("identifier should still be retrievable");

    let certs = resolved
        .certificates
        .expect("certificates relation should be populated");
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].id, cert_id);
    assert!(certs[0].deleted_at.is_some());
}
