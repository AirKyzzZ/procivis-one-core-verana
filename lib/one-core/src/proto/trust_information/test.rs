use std::sync::Arc;

use similar_asserts::assert_eq;
use time::macros::datetime;
use uuid::Uuid;

use crate::model::history::{
    GetHistoryList, History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    WalletRelayingPartyMetadata,
};
use crate::proto::trust_information::TrustInformationProvider;
use crate::proto::trust_information::provider::TrustInformationProviderImpl;
use crate::repository::history_repository::MockHistoryRepository;

fn dummy_history(action: HistoryAction, metadata: Option<HistoryMetadata>) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: datetime!(2023-01-01 12:00 UTC),
        action,
        name: "test".to_string(),
        target: None,
        source: HistorySource::Core,
        entity_id: None,
        entity_type: HistoryEntityType::Credential,
        metadata,
        organisation_id: None,
        user: None,
        metadata_blob_id: None,
    }
}

fn rp_metadata(name: &str) -> HistoryMetadata {
    HistoryMetadata::WalletRelayingParty(WalletRelayingPartyMetadata {
        name: name.to_string(),
        ..Default::default()
    })
}

#[tokio::test]
async fn test_find_trust_information_by_credential_id_success_rc() {
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();
    let created_date = datetime!(2023-01-01 12:00 UTC);

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![History {
                    created_date,
                    ..dummy_history(HistoryAction::WrpRcReceived, Some(rp_metadata("Test RP")))
                }],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = TrustInformationProviderImpl::new(Arc::new(history_repository));
    let result = provider
        .get_trust_information_by_credential_id(credential_id)
        .await
        .unwrap();

    assert!(result.is_some());
    let info = result.unwrap();
    assert_eq!(info.name, "Test RP");
    assert_eq!(info.received_at, created_date);
}

#[tokio::test]
async fn test_find_trust_information_by_credential_id_success_nr() {
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![dummy_history(
                    HistoryAction::WrpNrReceived,
                    Some(rp_metadata("Test RP NR")),
                )],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = TrustInformationProviderImpl::new(Arc::new(history_repository));
    let result = provider
        .get_trust_information_by_credential_id(credential_id)
        .await
        .unwrap();

    assert!(result.is_some());
    let info = result.unwrap();
    assert_eq!(info.name, "Test RP NR");
}

#[tokio::test]
async fn test_find_trust_information_none_when_empty() {
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
            })
        });

    let provider = TrustInformationProviderImpl::new(Arc::new(history_repository));
    let result = provider
        .get_trust_information_by_credential_id(credential_id)
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_find_trust_information_error_missing_metadata() {
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![dummy_history(HistoryAction::WrpRcReceived, None)],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = TrustInformationProviderImpl::new(Arc::new(history_repository));
    let result = provider
        .get_trust_information_by_credential_id(credential_id)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_find_trust_information_error_invalid_metadata_type() {
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![dummy_history(
                    HistoryAction::WrpRcReceived,
                    Some(HistoryMetadata::WalletUnitJWT("jwt".to_string())),
                )],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = TrustInformationProviderImpl::new(Arc::new(history_repository));
    let result = provider
        .get_trust_information_by_credential_id(credential_id)
        .await;

    assert!(result.is_err());
}
