use one_core::model::holder_wallet_instance::{
    CreateHolderWalletInstanceRequest, HolderWalletInstance, HolderWalletInstanceRelations,
    UpdateHolderWalletInstanceRequest,
};
use one_core::model::key::{Key, KeyRelations};
use one_core::model::organisation::Organisation;
use one_core::model::wallet_instance::{WalletInstanceStatus, WalletProviderType};
use one_core::model::wallet_instance_attestation::{
    WalletInstanceAttestation, WalletInstanceAttestationRelations,
};
use one_core::repository::holder_wallet_instance_repository::HolderWalletInstanceRepository;
use shared_types::HolderWalletInstanceId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::holder_wallet_instance::HolderWalletInstanceProvider;
use crate::test_utilities::{
    dummy_organisation, get_dummy_date, insert_key_to_database, insert_organisation_to_database,
    setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: HolderWalletInstanceProvider,
    pub organisation: Organisation,
    pub key: Key,
}

#[tokio::test]
async fn create_holder_wallet_instance_success() {
    let TestSetup {
        provider,
        organisation,
        key,
        ..
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    let result = provider
        .create(instance_to_create_request(test_wallet_instance(id, organisation, key)).await)
        .await;

    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(id, response);
}

#[tokio::test]
async fn get_holder_wallet_instance_success() {
    let TestSetup {
        provider,
        organisation,
        key,
        ..
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    provider
        .create(instance_to_create_request(test_wallet_instance(id, organisation, key)).await)
        .await
        .unwrap();

    let result = provider
        .get(&id, &HolderWalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();

    // no relations
    assert!(result.authentication_key.is_none());
    assert_eq!(result.id, id);
}

#[tokio::test]
async fn update_holder_wallet_instance_success() {
    let TestSetup {
        provider,
        organisation,
        key,
        ..
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    provider
        .create(
            instance_to_create_request(test_wallet_instance(id, organisation.clone(), key.clone()))
                .await,
        )
        .await
        .unwrap();

    let now = one_core::clock::now_utc();
    let update_request = UpdateHolderWalletInstanceRequest {
        status: Some(WalletInstanceStatus::Revoked),
        wallet_unit_attestations: Some(vec![WalletInstanceAttestation {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            expiration_date: now,
            attestation: "dummy attestation".to_string(),
            holder_wallet_unit_id: id,
            revocation_list_url: None,
            revocation_list_index: None,
            attested_key: Some(key.clone()),
        }]),
        trusted_rp_required: None,
    };

    provider.update(&id, update_request).await.unwrap();

    let reloaded = provider
        .get(
            &id,
            &HolderWalletInstanceRelations {
                wallet_unit_attestations: Some(WalletInstanceAttestationRelations {
                    attested_key: Some(KeyRelations::default()),
                }),
                authentication_key: Some(KeyRelations::default()),
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(reloaded.wallet_unit_attestations.is_some());
    assert_eq!(reloaded.wallet_unit_attestations.unwrap().len(), 1);
    assert_eq!(reloaded.organisation.id(), organisation.id);
    assert_eq!(reloaded.authentication_key.unwrap().id, key.id);
}

fn test_wallet_instance(
    id: HolderWalletInstanceId,
    organisation: Organisation,
    key: Key,
) -> HolderWalletInstance {
    let now = one_core::clock::now_utc();
    HolderWalletInstance {
        id,
        created_date: now,
        last_modified: now,
        status: WalletInstanceStatus::Pending,
        wallet_provider_type: WalletProviderType::ProcivisOne,
        wallet_provider_name: "test_name".to_string(),
        wallet_provider_url: "test_url".to_string(),
        organisation: organisation.into(),
        authentication_key: Some(key),
        provider_wallet_unit_id: Uuid::new_v4().into(),
        wallet_unit_attestations: None,
        trusted_rp_required: false,
    }
}

async fn instance_to_create_request(
    instance: HolderWalletInstance,
) -> CreateHolderWalletInstanceRequest {
    CreateHolderWalletInstanceRequest {
        id: instance.id,
        wallet_provider_type: instance.wallet_provider_type,
        wallet_provider_name: instance.wallet_provider_name,
        wallet_provider_url: instance.wallet_provider_url,
        provider_wallet_unit_id: instance.provider_wallet_unit_id,
        status: instance.status,
        organisation: instance.organisation.as_ref().await.unwrap().to_owned(),
        authentication_key: instance.authentication_key,
        trusted_rp_required: instance.trusted_rp_required,
    }
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    let key_id = insert_key_to_database(
        &db,
        "ED25519".to_string(),
        vec![],
        vec![],
        None,
        organisation_id,
    )
    .await
    .unwrap();
    TestSetup {
        provider: HolderWalletInstanceProvider {
            db: TransactionManagerImpl::new(db),
            organisation_repository: data_layer.organisation_repository,
            key_repository: data_layer.key_repository,
            wallet_unit_attestation_repository: data_layer.wallet_instance_attestation_repository,
        },
        organisation: dummy_organisation(Some(organisation_id)),
        key: Key {
            id: key_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: vec![],
            name: "test_key".to_string(),
            key_reference: Some("private".to_string().bytes().collect()),
            storage_type: "INTERNAL".to_string(),
            key_type: "ED25519".to_string(),
            organisation: dummy_organisation(Some(organisation_id)).into(),
        },
    }
}
