use std::collections::HashMap;
use std::sync::Arc;

use similar_asserts::assert_eq;
use standardized_types::etsi_119_602::MultiLangString;
use time::macros::datetime;
use uuid::Uuid;

use crate::model::history::{
    GetHistoryList, History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    TrustResolutionMetadata, TrustResolutionResult, WalletRelyingPartyMetadata,
};
use crate::proto::trust_information::TrustInformationProvider;
use crate::proto::trust_information::provider::TrustInformationProviderImpl;
use crate::provider::blob_storage_provider::MockBlobStorageProvider;
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

fn wrp_metadata(
    name: &str,
    purpose: HashMap<dcql::CredentialQueryId, Vec<MultiLangString>>,
) -> HistoryMetadata {
    HistoryMetadata::WalletRelyingParty(WalletRelyingPartyMetadata {
        name: name.to_string(),
        purpose,
    })
}

fn trust_resolved_metadata(result: TrustResolutionResult) -> HistoryMetadata {
    HistoryMetadata::TrustResolution(TrustResolutionMetadata { result })
}

fn provider(history_repository: MockHistoryRepository) -> TrustInformationProviderImpl {
    TrustInformationProviderImpl::new(
        Arc::new(history_repository),
        Arc::new(MockBlobStorageProvider::new()),
    )
}

#[tokio::test]
async fn test_find_trust_information_by_credential_id_success_rc() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();
    let created_date = datetime!(2024-01-01 12:00 UTC);

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![
                    dummy_history(
                        HistoryAction::WrpRcReceived,
                        Some(wrp_metadata("Test RP", Default::default())),
                    ),
                    History {
                        created_date,
                        ..dummy_history(
                            HistoryAction::TrustResolved,
                            Some(trust_resolved_metadata(TrustResolutionResult::Trusted)),
                        )
                    },
                ],
                total_items: 2,
                total_pages: 1,
            })
        });

    let provider = provider(history_repository);

    // when
    let result = provider.get_trust_information(credential_id).await.unwrap();

    // then
    assert_eq!(result.len(), 1);
    let info = result.into_iter().next().unwrap();
    assert_eq!(info.name.unwrap(), "Test RP");
    assert_eq!(info.received_at, created_date);
}

#[tokio::test]
async fn test_find_trust_information_by_credential_id_success_nr() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![
                    dummy_history(
                        HistoryAction::WrpNrReceived,
                        Some(wrp_metadata("Test RP NR", Default::default())),
                    ),
                    dummy_history(
                        HistoryAction::TrustResolved,
                        Some(trust_resolved_metadata(TrustResolutionResult::Trusted)),
                    ),
                ],
                total_items: 2,
                total_pages: 1,
            })
        });

    let provider = provider(history_repository);

    // when
    let result = provider.get_trust_information(credential_id).await.unwrap();

    // then
    assert_eq!(result.len(), 1);
    let info = result.into_iter().next().unwrap();
    assert_eq!(info.name.unwrap(), "Test RP NR");
    assert_eq!(info.result, TrustResolutionResult::Trusted);
}

#[tokio::test]
async fn test_find_trust_information_none_when_empty() {
    // given
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

    let provider = provider(history_repository);

    // when
    let result = provider.get_trust_information(credential_id).await.unwrap();

    // then
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_find_trust_information_by_credential_id_success_no_name() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![dummy_history(
                    HistoryAction::TrustResolved,
                    Some(trust_resolved_metadata(TrustResolutionResult::Untrusted)),
                )],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = provider(history_repository);

    // when
    let result = provider.get_trust_information(credential_id).await.unwrap();

    // then
    assert_eq!(result.len(), 1);
    let info = result.into_iter().next().unwrap();
    assert_eq!(info.name, None);
    assert_eq!(info.result, TrustResolutionResult::Untrusted);
}

#[tokio::test]
async fn test_find_trust_information_error_missing_metadata() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![dummy_history(HistoryAction::TrustResolved, None)],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = provider(history_repository);

    // when
    let result = provider.get_trust_information(credential_id).await;

    // then
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_trust_purpose_success() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();
    let query_id: dcql::CredentialQueryId = "query-1".into();
    let purpose = vec![MultiLangString {
        lang: "en".to_string(),
        value: "Test purpose".to_string(),
    }];

    let mut purposes = HashMap::new();
    purposes.insert(query_id.clone(), purpose.clone());

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![dummy_history(
                    HistoryAction::WrpRcReceived,
                    Some(wrp_metadata("Test RP", purposes.clone())),
                )],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = provider(history_repository);

    // when
    let result = provider
        .get_trust_purpose(credential_id, &query_id)
        .await
        .unwrap();

    // then
    assert!(result.is_some());
    let info = result.unwrap();
    assert_eq!(info.purpose.0.get("en").unwrap(), "Test purpose");
}

#[tokio::test]
async fn test_get_trust_purpose_none_when_query_id_missing() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();
    let query_id: dcql::CredentialQueryId = "query-1".into();
    let other_query_id: dcql::CredentialQueryId = "query-2".into();
    let purpose = vec![MultiLangString {
        lang: "en".to_string(),
        value: "Test purpose".to_string(),
    }];

    let mut purposes = HashMap::new();
    purposes.insert(other_query_id, purpose);

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![dummy_history(
                    HistoryAction::WrpRcReceived,
                    Some(wrp_metadata("Test RP", purposes.clone())),
                )],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = provider(history_repository);

    // when
    let result = provider
        .get_trust_purpose(credential_id, &query_id)
        .await
        .unwrap();

    // then
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_trust_purpose_none_when_empty() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();
    let query_id: dcql::CredentialQueryId = "query-1".into();

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

    let provider = provider(history_repository);

    // when
    let result = provider
        .get_trust_purpose(credential_id, &query_id)
        .await
        .unwrap();

    // then
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_trust_purpose_error_missing_metadata() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();
    let query_id: dcql::CredentialQueryId = "query-1".into();

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

    let provider = provider(history_repository);

    // when
    let result = provider.get_trust_purpose(credential_id, &query_id).await;

    // then
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_trust_purpose_error_invalid_metadata_type() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();
    let query_id: dcql::CredentialQueryId = "query-1".into();

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

    let provider = provider(history_repository);

    // when
    let result = provider.get_trust_purpose(credential_id, &query_id).await;

    // then
    assert!(result.is_err());
}

#[tokio::test]
async fn test_find_trust_information_error_invalid_metadata_type() {
    // given
    let mut history_repository = MockHistoryRepository::new();
    let credential_id = Uuid::new_v4().into();

    history_repository
        .expect_get_history_list()
        .once()
        .returning(move |_| {
            Ok(GetHistoryList {
                values: vec![dummy_history(
                    HistoryAction::TrustResolved,
                    Some(HistoryMetadata::WalletUnitJWT("jwt".to_string())),
                )],
                total_items: 1,
                total_pages: 1,
            })
        });

    let provider = provider(history_repository);

    // when
    let result = provider.get_trust_information(credential_id).await;

    // then
    assert!(result.is_err());
}
