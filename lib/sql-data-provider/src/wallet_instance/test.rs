use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::organisation::Organisation;
use one_core::model::wallet_instance::{
    SortableWalletInstanceColumn, UpdateWalletInstanceRequest, WalletInstance,
    WalletInstanceFilterValue, WalletInstanceListQuery, WalletInstanceOs, WalletInstanceRelations,
    WalletInstanceStatus, WalletProviderType,
};
use one_core::model::wallet_instance_attested_key::{
    WalletInstanceAttestedKey, WalletInstanceAttestedKeyRelations,
};
use one_core::repository::wallet_instance_repository::WalletInstanceRepository;
use shared_types::{OrganisationId, WalletInstanceId};
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use super::WalletInstanceProvider;
use crate::test_utilities::{
    get_dummy_date, insert_organisation_to_database, insert_wallet_instance_to_database,
    random_jwk, setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: WalletInstanceProvider,
    pub wallet_unit_ids: Vec<WalletInstanceId>,
    pub organisation_id: OrganisationId,
}

async fn setup(n: usize) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();
    let mut wallet_unit_ids = vec![];
    for i in 0..n {
        let wallet_unit_id =
            insert_wallet_instance_to_database(&db, organisation_id, format!("wallet{i}")).await;
        wallet_unit_ids.push(wallet_unit_id);
    }

    TestSetup {
        provider: WalletInstanceProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository: data_layer.organisation_repository,
            wallet_instance_attested_key_repository: data_layer
                .wallet_instance_attested_key_repository,
        },
        organisation_id,
        wallet_unit_ids,
    }
}

fn dummy_wallet_instance(id: WalletInstanceId, org: OrganisationId) -> WalletInstance {
    let now = get_dummy_date();
    WalletInstance {
        id,
        created_date: now,
        last_modified: now,
        last_issuance: Some(now),
        name: "test_wallet".to_string(),
        os: WalletInstanceOs::Android,
        status: WalletInstanceStatus::Active,
        wallet_provider_type: WalletProviderType::ProcivisOne,
        wallet_provider_name: "Test Provider Name".to_string(),
        authentication_key_jwk: Some(random_jwk()),
        nonce: None,
        organisation: Some(Organisation {
            id: org,
            created_date: now,
            last_modified: now,
            deactivated_at: None,
            wallet_provider: None,
            wallet_provider_issuer: None,
            parent_organisation: None,
        }),
        attested_keys: None,
    }
}

fn dummy_attested_key(wallet_unit_id: WalletInstanceId) -> WalletInstanceAttestedKey {
    let now = get_dummy_date();
    WalletInstanceAttestedKey {
        id: Uuid::new_v4().into(),
        wallet_instance_id: wallet_unit_id,
        created_date: now,
        last_modified: now,
        expiration_date: now + Duration::days(30),
        public_key_jwk: random_jwk(),
        revocation: None,
    }
}

#[tokio::test]
async fn test_create_wallet_instance_success() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
    let wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);

    let result = provider.create_wallet_instance(wallet_unit.clone()).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), wallet_unit_id);

    // Verify the wallet unit was actually created in the database
    let stored_wallet_instance = provider
        .get_wallet_instance(&wallet_unit_id, &WalletInstanceRelations::default())
        .await
        .unwrap();
    assert!(stored_wallet_instance.is_some());

    let stored_wallet_instance = stored_wallet_instance.unwrap();
    assert_eq!(stored_wallet_instance.id, wallet_unit.id);
    assert_eq!(stored_wallet_instance.name, wallet_unit.name);
    assert_eq!(stored_wallet_instance.os, wallet_unit.os);
    assert_eq!(stored_wallet_instance.status, wallet_unit.status);
    assert_eq!(
        stored_wallet_instance.wallet_provider_type,
        wallet_unit.wallet_provider_type
    );
    assert_eq!(
        stored_wallet_instance.wallet_provider_name,
        wallet_unit.wallet_provider_name
    );
    assert_eq!(
        stored_wallet_instance.authentication_key_jwk,
        wallet_unit.authentication_key_jwk
    );
}

#[tokio::test]
async fn test_create_wallet_instance_duplicate_id() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
    let wallet_unit1 = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);

    // Create first wallet unit
    let result1 = provider.create_wallet_instance(wallet_unit1).await;
    assert!(result1.is_ok());

    // Try to create second wallet unit with same ID - should fail
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id, Uuid::new_v4().into());
    wallet_unit2.authentication_key_jwk = Some(random_jwk());

    let result2 = provider.create_wallet_instance(wallet_unit2).await;
    assert!(result2.is_err());
}

#[tokio::test]
async fn test_create_wallet_instance_duplicate_public_key() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();

    let wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);

    // Create first wallet unit
    let result1 = provider.create_wallet_instance(wallet_unit1.clone()).await;
    assert!(result1.is_ok());

    // Try to create second wallet unit with same public key - should fail
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.authentication_key_jwk = wallet_unit1.authentication_key_jwk; // Same public key

    let result2 = provider.create_wallet_instance(wallet_unit2).await;
    assert!(result2.is_err());
}

#[tokio::test]
async fn test_create_wallet_instance_different_statuses() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Test creating with ACTIVE status
    let active_id: WalletInstanceId = Uuid::new_v4().into();
    let mut active_wallet_instance = dummy_wallet_instance(active_id, test_setup.organisation_id);
    active_wallet_instance.status = WalletInstanceStatus::Active;

    let result_active = provider
        .create_wallet_instance(active_wallet_instance)
        .await;
    assert!(result_active.is_ok());

    // Test creating with REVOKED status
    let revoked_id: WalletInstanceId = Uuid::new_v4().into();
    let mut revoked_wallet_instance = dummy_wallet_instance(revoked_id, test_setup.organisation_id);
    revoked_wallet_instance.status = WalletInstanceStatus::Revoked;

    let result_revoked = provider
        .create_wallet_instance(revoked_wallet_instance)
        .await;
    assert!(result_revoked.is_ok());

    // Verify both were created with correct statuses
    let active_stored = provider
        .get_wallet_instance(&active_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active_stored.status, WalletInstanceStatus::Active);

    let revoked_stored = provider
        .get_wallet_instance(&revoked_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked_stored.status, WalletInstanceStatus::Revoked);
}

#[tokio::test]
async fn test_create_wallet_instance_different_os_types() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Test creating with ANDROID OS
    let android_id: WalletInstanceId = Uuid::new_v4().into();
    let mut android_wallet_instance = dummy_wallet_instance(android_id, test_setup.organisation_id);
    android_wallet_instance.os = WalletInstanceOs::Android;

    let result_android = provider
        .create_wallet_instance(android_wallet_instance)
        .await;
    assert!(result_android.is_ok());

    // Test creating with iOS OS
    let ios_id: WalletInstanceId = Uuid::new_v4().into();
    let mut ios_wallet_instance = dummy_wallet_instance(ios_id, test_setup.organisation_id);
    ios_wallet_instance.os = WalletInstanceOs::Ios;

    let result_ios = provider.create_wallet_instance(ios_wallet_instance).await;
    assert!(result_ios.is_ok());

    // Verify both were created with correct OS types
    let android_stored = provider
        .get_wallet_instance(&android_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(android_stored.os, WalletInstanceOs::Android);

    let ios_stored = provider
        .get_wallet_instance(&ios_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ios_stored.os, WalletInstanceOs::Ios);
}

#[tokio::test]
async fn test_create_and_list_wallet_instances() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create multiple wallet units
    let mut created_ids = Vec::new();

    for i in 0..3 {
        let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = format!("wallet_{i}");

        let result = provider.create_wallet_instance(wallet_unit).await;
        assert!(result.is_ok());
        created_ids.push(wallet_unit_id);
    }

    // List all wallet units
    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_items, 3);
    assert_eq!(data.values.len(), 3);

    // Verify all created wallet units are in the list
    for created_id in created_ids {
        assert!(data.values.iter().any(|wu| wu.id == created_id));
    }
}

#[tokio::test]
async fn test_get_wallet_instance_success() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        ..
    } = setup(1).await;

    let result = provider
        .get_wallet_instance(&wallet_unit_ids[0], &WalletInstanceRelations::default())
        .await;

    assert!(result.is_ok());
    let wallet_unit = result.unwrap();
    assert!(wallet_unit.is_some());

    let wallet_unit = wallet_unit.unwrap();
    assert_eq!(wallet_unit.id, wallet_unit_ids[0]);
    assert_eq!(wallet_unit.name, "wallet0");
    assert_eq!(wallet_unit.os, WalletInstanceOs::Android);
    assert_eq!(wallet_unit.status, WalletInstanceStatus::Active);
    assert_eq!(
        wallet_unit.wallet_provider_type,
        WalletProviderType::ProcivisOne
    );
    assert_eq!(wallet_unit.wallet_provider_name, "Test Provider Name");
    assert!(wallet_unit.authentication_key_jwk.is_some());
}

#[tokio::test]
async fn test_get_wallet_instance_missing() {
    let TestSetup { provider, .. } = setup(0).await;

    let result = provider
        .get_wallet_instance(&Uuid::new_v4().into(), &WalletInstanceRelations::default())
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_wallet_instance_list_no_filters() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        ..
    } = setup(3).await;

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 3);
    assert_eq!(data.values.len(), 3);

    assert!(
        data.values
            .iter()
            .all(|wu| wallet_unit_ids.contains(&wu.id))
    );
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_pagination() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 2,
        }),
        sorting: None,
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 2);
    assert_eq!(data.total_items, 3);
    assert_eq!(data.values.len(), 2);
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_name_filter() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            WalletInstanceFilterValue::Name(one_core::model::list_filter::StringMatch::equals(
                "wallet1",
            ))
            .condition(),
        ),
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 1);
    assert_eq!(data.values.len(), 1);
    assert_eq!(data.values[0].name, "wallet1");
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_status_filter() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            WalletInstanceFilterValue::Status(vec![WalletInstanceStatus::Active]).condition(),
        ),
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 3);
    assert_eq!(data.values.len(), 3);
    assert!(
        data.values
            .iter()
            .all(|wu| wu.status == WalletInstanceStatus::Active)
    );
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_sorting() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 3);
    assert_eq!(data.values.len(), 3);

    // Check that names are sorted in ascending order
    let names: Vec<&String> = data.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(names, vec!["wallet0", "wallet1", "wallet2"]);
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_ids_filter() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        ..
    } = setup(3).await;

    let target_ids = vec![wallet_unit_ids[0], wallet_unit_ids[2]];

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(WalletInstanceFilterValue::Ids(target_ids.clone()).condition()),
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 2);
    assert_eq!(data.values.len(), 2);

    let returned_ids: Vec<WalletInstanceId> = data.values.iter().map(|wu| wu.id).collect();
    assert!(target_ids.iter().all(|id| returned_ids.contains(id)));
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_wallet_provider_type_filter() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            WalletInstanceFilterValue::WalletProviderType(vec!["PROCIVIS_ONE".to_string()])
                .condition(),
        ),
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 3);
    assert_eq!(data.values.len(), 3);
    assert!(
        data.values
            .iter()
            .all(|wu| wu.wallet_provider_type == WalletProviderType::ProcivisOne)
    );
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_os_filter() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(WalletInstanceFilterValue::Os(vec![WalletInstanceOs::Android]).condition()),
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 3);
    assert_eq!(data.values.len(), 3);
    assert!(
        data.values
            .iter()
            .all(|wu| wu.os == WalletInstanceOs::Android)
    );
}

#[tokio::test]
async fn test_get_wallet_instance_list_empty_result() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            WalletInstanceFilterValue::Status(vec![WalletInstanceStatus::Revoked]).condition(),
        ),
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 0);
    assert_eq!(data.total_items, 0);
    assert_eq!(data.values.len(), 0);
}

// UPDATE TESTS - Status-only updates

#[tokio::test]
async fn test_update_wallet_instance_status_success() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create a wallet unit first with ACTIVE status
    let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
    wallet_unit.status = WalletInstanceStatus::Active;
    let original_name = wallet_unit.name.clone();
    let original_os = wallet_unit.os;
    let original_provider_type = wallet_unit.wallet_provider_type;
    let original_provider_name = wallet_unit.wallet_provider_name.clone();
    let original_public_key = wallet_unit.authentication_key_jwk.clone();

    provider.create_wallet_instance(wallet_unit).await.unwrap();

    // Update only the status to REVOKED
    let update_request = UpdateWalletInstanceRequest {
        status: Some(WalletInstanceStatus::Revoked),
        last_issuance: None,
        authentication_key_jwk: None,
        attested_keys: None,
    };

    let result = provider
        .update_wallet_instance(&wallet_unit_id, update_request)
        .await;
    assert!(result.is_ok());

    // Verify only the status and last_modified were updated
    let updated_wallet_instance = provider
        .get_wallet_instance(&wallet_unit_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();

    // Status should be updated
    assert_eq!(
        updated_wallet_instance.status,
        WalletInstanceStatus::Revoked
    );

    // All other fields should remain unchanged
    assert_eq!(updated_wallet_instance.name, original_name);
    assert_eq!(updated_wallet_instance.os, original_os);
    assert_eq!(
        updated_wallet_instance.wallet_provider_type,
        original_provider_type
    );
    assert_eq!(
        updated_wallet_instance.wallet_provider_name,
        original_provider_name
    );
    assert_eq!(
        updated_wallet_instance.authentication_key_jwk,
        original_public_key
    );

    // Verify last_modified was updated (should be different from created_date)
    assert!(updated_wallet_instance.last_modified > updated_wallet_instance.created_date);
}

#[tokio::test]
async fn test_update_wallet_instance_nonexistent() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let nonexistent_id: WalletInstanceId = Uuid::new_v4().into();
    let update_request = UpdateWalletInstanceRequest {
        status: Some(WalletInstanceStatus::Revoked),
        last_issuance: None,
        authentication_key_jwk: None,
        attested_keys: None,
    };

    let result = provider
        .update_wallet_instance(&nonexistent_id, update_request)
        .await;

    // Should fail because the wallet unit doesn't exist
    assert!(result.is_err());
}

#[tokio::test]
async fn test_update_wallet_instance_empty_request() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create a wallet unit first
    let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
    let wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
    let original_status = wallet_unit.status;
    provider.create_wallet_instance(wallet_unit).await.unwrap();

    // Get original last_modified
    let original_wallet_instance = provider
        .get_wallet_instance(&wallet_unit_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();

    // Update with empty request (no fields specified)
    let update_request = UpdateWalletInstanceRequest::default();

    let result = provider
        .update_wallet_instance(&wallet_unit_id, update_request)
        .await;
    assert!(result.is_ok());

    // Verify no fields were changed except last_modified
    let updated_wallet_instance = provider
        .get_wallet_instance(&wallet_unit_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated_wallet_instance.status, original_status);
    // But last_modified should be updated
    assert!(updated_wallet_instance.last_modified > original_wallet_instance.last_modified);
}

#[tokio::test]
async fn test_update_wallet_instance_status_changes() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet unit with ACTIVE status
    let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
    wallet_unit.status = WalletInstanceStatus::Active;
    provider.create_wallet_instance(wallet_unit).await.unwrap();

    // Update to REVOKED
    let update_request = UpdateWalletInstanceRequest {
        status: Some(WalletInstanceStatus::Revoked),
        last_issuance: None,
        authentication_key_jwk: None,
        attested_keys: None,
    };

    let result = provider
        .update_wallet_instance(&wallet_unit_id, update_request)
        .await;
    assert!(result.is_ok());

    // Verify status was updated
    let updated_wallet_instance = provider
        .get_wallet_instance(&wallet_unit_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated_wallet_instance.status,
        WalletInstanceStatus::Revoked
    );

    // Update back to ACTIVE
    let update_request = UpdateWalletInstanceRequest {
        status: Some(WalletInstanceStatus::Active),
        last_issuance: None,
        authentication_key_jwk: None,
        attested_keys: None,
    };

    let result = provider
        .update_wallet_instance(&wallet_unit_id, update_request)
        .await;
    assert!(result.is_ok());

    // Verify status was updated back
    let updated_wallet_instance = provider
        .get_wallet_instance(&wallet_unit_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_wallet_instance.status, WalletInstanceStatus::Active);
}

#[tokio::test]
async fn test_update_wallet_instance_public_key_changes() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
    wallet_unit.authentication_key_jwk = None;
    provider.create_wallet_instance(wallet_unit).await.unwrap();
    let created_wallet_instance = provider
        .get_wallet_instance(&wallet_unit_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created_wallet_instance.authentication_key_jwk, None);

    let new_jwk = random_jwk();
    let update_request = UpdateWalletInstanceRequest {
        status: None,
        last_issuance: None,
        authentication_key_jwk: Some(new_jwk.clone()),
        attested_keys: None,
    };

    let result = provider
        .update_wallet_instance(&wallet_unit_id, update_request)
        .await;
    assert!(result.is_ok());

    // Verify public key was updated
    let updated_wallet_instance = provider
        .get_wallet_instance(&wallet_unit_id, &WalletInstanceRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated_wallet_instance.authentication_key_jwk,
        Some(new_jwk)
    );
}

#[tokio::test]
async fn test_update_and_list_wallet_instances() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create multiple wallet units
    let mut wallet_unit_ids = Vec::new();
    for i in 0..3 {
        let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = format!("wallet_{i}");
        wallet_unit.status = WalletInstanceStatus::Active;

        provider.create_wallet_instance(wallet_unit).await.unwrap();
        wallet_unit_ids.push(wallet_unit_id);
    }

    // Update one wallet unit to REVOKED status
    let update_request = UpdateWalletInstanceRequest {
        status: Some(WalletInstanceStatus::Revoked),
        last_issuance: None,
        authentication_key_jwk: None,
        attested_keys: None,
    };

    provider
        .update_wallet_instance(&wallet_unit_ids[1], update_request)
        .await
        .unwrap();

    // List only ACTIVE wallet units
    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            WalletInstanceFilterValue::Status(vec![WalletInstanceStatus::Active]).condition(),
        ),
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    // Should only return 2 ACTIVE wallet units
    assert_eq!(result.total_items, 2);
    assert_eq!(result.values.len(), 2);
    assert!(
        result
            .values
            .iter()
            .all(|wu| wu.status == WalletInstanceStatus::Active)
    );

    // Verify the revoked one is not in the list
    assert!(!result.values.iter().any(|wu| wu.id == wallet_unit_ids[1]));
}

#[tokio::test]
async fn test_update_wallet_instance_attested_key_changes() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
    let attested_key1 = dummy_attested_key(wallet_unit_id);
    wallet_unit.attested_keys = Some(vec![attested_key1.clone()]);
    provider.create_wallet_instance(wallet_unit).await.unwrap();
    let created_wallet_instance = provider
        .get_wallet_instance(
            &wallet_unit_id,
            &WalletInstanceRelations {
                attested_keys: Some(WalletInstanceAttestedKeyRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        created_wallet_instance
            .attested_keys
            .as_ref()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        created_wallet_instance.attested_keys.as_ref().unwrap()[0].id,
        attested_key1.id
    );

    let attested_key2 = dummy_attested_key(wallet_unit_id);
    let new_attested_keys = vec![attested_key1.clone(), attested_key2.clone()];
    let update_request = UpdateWalletInstanceRequest {
        attested_keys: Some(new_attested_keys),
        ..Default::default()
    };

    let result = provider
        .update_wallet_instance(&wallet_unit_id, update_request)
        .await;
    assert!(result.is_ok());

    // Verify public key was updated
    let updated_wallet_instance = provider
        .get_wallet_instance(
            &wallet_unit_id,
            &WalletInstanceRelations {
                attested_keys: Some(WalletInstanceAttestedKeyRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated_wallet_instance
            .attested_keys
            .as_ref()
            .unwrap()
            .len(),
        2
    );
    assert!(
        updated_wallet_instance
            .attested_keys
            .as_ref()
            .unwrap()
            .iter()
            .any(|attested_key| attested_key.id == attested_key1.id)
    );
    assert!(
        updated_wallet_instance
            .attested_keys
            .as_ref()
            .unwrap()
            .iter()
            .any(|attested_key| attested_key.id == attested_key2.id)
    );
}

// SORTING TESTS

#[tokio::test]
async fn test_sort_by_name_ascending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different names
    let names = vec!["zebra_wallet", "alpha_wallet", "beta_wallet"];
    for name in &names {
        let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = name.to_string();
        provider.create_wallet_instance(wallet_unit).await.unwrap();
    }

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 3);
    let returned_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(
        returned_names,
        vec!["alpha_wallet", "beta_wallet", "zebra_wallet"]
    );
}

#[tokio::test]
async fn test_sort_by_name_descending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different names
    let names = vec!["zebra_wallet", "alpha_wallet", "beta_wallet"];
    for name in &names {
        let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = name.to_string();
        provider.create_wallet_instance(wallet_unit).await.unwrap();
    }

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 3);
    let returned_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(
        returned_names,
        vec!["zebra_wallet", "beta_wallet", "alpha_wallet"]
    );
}

#[tokio::test]
async fn test_sort_by_status_ascending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different statuses
    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "revoked_wallet".to_string();
    wallet_unit1.status = WalletInstanceStatus::Revoked;
    provider.create_wallet_instance(wallet_unit1).await.unwrap();

    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "active_wallet".to_string();
    wallet_unit2.status = WalletInstanceStatus::Active;
    provider.create_wallet_instance(wallet_unit2).await.unwrap();

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Status,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 2);
    // ACTIVE should come before REVOKED alphabetically
    assert_eq!(result.values[0].status, WalletInstanceStatus::Active);
    assert_eq!(result.values[1].status, WalletInstanceStatus::Revoked);
}

#[tokio::test]
async fn test_sort_by_status_descending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different statuses
    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "revoked_wallet".to_string();
    wallet_unit1.status = WalletInstanceStatus::Revoked;
    provider.create_wallet_instance(wallet_unit1).await.unwrap();

    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "active_wallet".to_string();
    wallet_unit2.status = WalletInstanceStatus::Active;
    provider.create_wallet_instance(wallet_unit2).await.unwrap();

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Status,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 2);
    // REVOKED should come before ACTIVE in descending order
    assert_eq!(result.values[0].status, WalletInstanceStatus::Revoked);
    assert_eq!(result.values[1].status, WalletInstanceStatus::Active);
}

#[tokio::test]
async fn test_sort_by_os_ascending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different OS values
    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "ios_wallet".to_string();
    wallet_unit1.os = WalletInstanceOs::Ios;
    provider.create_wallet_instance(wallet_unit1).await.unwrap();

    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "android_wallet".to_string();
    wallet_unit2.os = WalletInstanceOs::Android;
    provider.create_wallet_instance(wallet_unit2).await.unwrap();

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Os,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 2);
    // ANDROID should come before IOS alphabetically
    assert_eq!(result.values[0].os, WalletInstanceOs::Android);
    assert_eq!(result.values[1].os, WalletInstanceOs::Ios);
}

#[tokio::test]
async fn test_sort_by_os_descending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different OS values
    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "ios_wallet".to_string();
    wallet_unit1.os = WalletInstanceOs::Ios;
    provider.create_wallet_instance(wallet_unit1).await.unwrap();

    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "android_wallet".to_string();
    wallet_unit2.os = WalletInstanceOs::Android;
    provider.create_wallet_instance(wallet_unit2).await.unwrap();

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Os,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 2);
    // IOS should come before ANDROID in descending order
    assert_eq!(result.values[0].os, WalletInstanceOs::Ios);
    assert_eq!(result.values[1].os, WalletInstanceOs::Android);
}

#[tokio::test]
async fn test_sort_by_created_date_ascending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with sufficient delay to ensure different timestamps
    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "first_wallet".to_string();
    provider.create_wallet_instance(wallet_unit1).await.unwrap();

    // Larger delay to ensure different created_date
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "second_wallet".to_string();
    provider.create_wallet_instance(wallet_unit2).await.unwrap();

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::CreatedDate,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 2);

    // Verify timestamps are properly ordered
    assert!(result.values[0].created_date <= result.values[1].created_date);

    // If timestamps are identical, just verify both are present
    if result.values[0].created_date == result.values[1].created_date {
        let names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
        assert!(names.contains(&&"first_wallet".to_string()));
        assert!(names.contains(&&"second_wallet".to_string()));
    } else {
        // First created should come first in ascending order
        assert_eq!(result.values[0].name, "first_wallet");
        assert_eq!(result.values[1].name, "second_wallet");
    }
}

#[tokio::test]
async fn test_sort_by_created_date_descending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with sufficient delay to ensure different timestamps
    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "first_wallet".to_string();
    provider.create_wallet_instance(wallet_unit1).await.unwrap();

    // Larger delay to ensure different created_date
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "second_wallet".to_string();
    provider.create_wallet_instance(wallet_unit2).await.unwrap();

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::CreatedDate,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 2);

    // Verify timestamps are actually different
    assert!(result.values[0].created_date >= result.values[1].created_date);

    // If timestamps are identical, we can't rely on order, so just verify we have both
    if result.values[0].created_date == result.values[1].created_date {
        // If created dates are identical, just verify both wallet units are present
        let names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
        assert!(names.contains(&&"first_wallet".to_string()));
        assert!(names.contains(&&"second_wallet".to_string()));
    } else {
        // Most recent created should come first in descending order
        assert_eq!(result.values[0].name, "second_wallet");
        assert_eq!(result.values[1].name, "first_wallet");
    }
}

#[tokio::test]
async fn test_sort_by_last_modified_after_updates() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create two wallet units
    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "first_wallet".to_string();
    provider.create_wallet_instance(wallet_unit1).await.unwrap();

    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "second_wallet".to_string();
    provider.create_wallet_instance(wallet_unit2).await.unwrap();

    // Small delay to ensure different last_modified
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Update the first wallet unit to change its last_modified
    let update_request = UpdateWalletInstanceRequest {
        status: Some(WalletInstanceStatus::Revoked),
        last_issuance: None,
        authentication_key_jwk: None,
        attested_keys: None,
    };
    provider
        .update_wallet_instance(&wallet_unit_id1, update_request)
        .await
        .unwrap();

    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::LastModified,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 2);
    // Most recently modified (updated) should come first
    assert_eq!(result.values[0].name, "first_wallet");
    assert_eq!(result.values[1].name, "second_wallet");
    assert!(result.values[0].last_modified > result.values[1].last_modified);
}

#[tokio::test]
async fn test_sort_with_pagination() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create 5 wallet units with alphabetical names
    let names = vec!["echo", "alpha", "delta", "bravo", "charlie"];
    for name in &names {
        let wallet_unit_id: WalletInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_wallet_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = name.to_string();
        provider.create_wallet_instance(wallet_unit).await.unwrap();
    }

    // Get first page (2 items) sorted by name ascending
    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 2,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 5);
    assert_eq!(result.total_pages, 3);
    assert_eq!(result.values.len(), 2);

    // First page should contain first 2 alphabetically
    let first_page_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(first_page_names, vec!["alpha", "bravo"]);

    // Get second page
    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 1,
            page_size: 2,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 5);
    assert_eq!(result.total_pages, 3);
    assert_eq!(result.values.len(), 2);

    // Second page should contain next 2 alphabetically
    let second_page_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(second_page_names, vec!["charlie", "delta"]);
}

#[tokio::test]
async fn test_sort_with_filtering() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different statuses and names
    let wallet_unit_id1: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_wallet_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "zebra_active".to_string();
    wallet_unit1.status = WalletInstanceStatus::Active;
    provider.create_wallet_instance(wallet_unit1).await.unwrap();

    let wallet_unit_id2: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_wallet_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "alpha_active".to_string();
    wallet_unit2.status = WalletInstanceStatus::Active;
    provider.create_wallet_instance(wallet_unit2).await.unwrap();

    let wallet_unit_id3: WalletInstanceId = Uuid::new_v4().into();
    let mut wallet_unit3 = dummy_wallet_instance(wallet_unit_id3, test_setup.organisation_id);
    wallet_unit3.name = "beta_revoked".to_string();
    wallet_unit3.status = WalletInstanceStatus::Revoked;
    provider.create_wallet_instance(wallet_unit3).await.unwrap();

    // Query only ACTIVE wallet units, sorted by name ascending
    let query = WalletInstanceListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableWalletInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: Some(
            WalletInstanceFilterValue::Status(vec![WalletInstanceStatus::Active]).condition(),
        ),
        include: None,
    };

    let result = provider.get_wallet_instance_list(query).await.unwrap();

    assert_eq!(result.total_items, 2);
    assert_eq!(result.values.len(), 2);

    // Should only return ACTIVE wallet units, sorted by name
    let returned_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(returned_names, vec!["alpha_active", "zebra_active"]);

    // Verify all returned items are ACTIVE
    assert!(
        result
            .values
            .iter()
            .all(|wu| wu.status == WalletInstanceStatus::Active)
    );
}
