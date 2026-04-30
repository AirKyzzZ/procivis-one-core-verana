use std::sync::Arc;

use HolderWalletInstanceFilterValue::Status;
use one_dto_mapper::convert_inner;
use serde_json::{Value, json};
use shared_types::{HolderWalletInstanceId, OrganisationId, VerifierInstanceId};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::holder_wallet_instance::{
    HolderWalletInstance, HolderWalletInstanceFilterValue, HolderWalletInstanceListQuery,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::model::verifier_instance::{VerifierInstance, VerifierInstanceListQuery};
use crate::model::wallet_instance::WalletInstanceStatus;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::trust_collection::dto::RemoteTrustCollectionInfoDTO;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::task::Task;
use crate::repository::holder_wallet_instance_repository::HolderWalletInstanceRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::verifier_instance_repository::VerifierInstanceRepository;
use crate::service::error::ServiceError;

#[cfg(test)]
mod test;

pub(crate) struct TrustCollectionSyncTask {
    wallet_instance_repository: Arc<dyn HolderWalletInstanceRepository>,
    wallet_unit_client: Arc<dyn WalletProviderClient>,
    verifier_instance_repository: Arc<dyn VerifierInstanceRepository>,
    verifier_client: Arc<dyn VerifierProviderClient>,
    trust_collection_sync: Arc<dyn TrustCollectionManager>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    subscription_sync: Arc<dyn TrustListSubscriptionSync>,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustCollectionSyncError {
    #[error("Invalid task params: {0}")]
    InvalidParams(#[from] serde_json::Error),
    #[error("Wallet unit not found: {0}")]
    WalletUnitNotFound(HolderWalletInstanceId),
    #[error("Verifier instance not found: {0}")]
    VerifierInstanceNotFound(VerifierInstanceId),
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TrustCollectionSyncError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidParams(_) => ErrorCode::BR_0405,
            Self::WalletUnitNotFound(_) => ErrorCode::BR_0259,
            Self::VerifierInstanceNotFound(_) => ErrorCode::BR_0406,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested_error) => nested_error.error_code(),
        }
    }
}

#[async_trait::async_trait]
impl Task for TrustCollectionSyncTask {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let result = self
            .run_internal()
            .await
            .error_while("syncing trust collections")?;
        Ok(result)
    }
}

struct RemoteCollectionData {
    organisation_id: OrganisationId,
    provider_url: String,
    remote_collections: Vec<RemoteTrustCollectionInfoDTO>,
}

impl TrustCollectionSyncTask {
    pub fn new(
        wallet_instance_repository: Arc<dyn HolderWalletInstanceRepository>,
        wallet_unit_client: Arc<dyn WalletProviderClient>,
        verifier_instance_repository: Arc<dyn VerifierInstanceRepository>,
        verifier_client: Arc<dyn VerifierProviderClient>,
        trust_collection_sync: Arc<dyn TrustCollectionManager>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        subscription_sync: Arc<dyn TrustListSubscriptionSync>,
    ) -> Self {
        Self {
            wallet_instance_repository,
            wallet_unit_client,
            verifier_instance_repository,
            verifier_client,
            trust_collection_sync,
            trust_collection_repository,
            subscription_sync,
        }
    }
    async fn run_internal(&self) -> Result<Value, TrustCollectionSyncError> {
        let synced_collections_count = self.sync_wallet_instance_collections().await?
            + self.sync_verifier_instance_collections().await?;
        Ok(json!({
            "syncedTrustCollectionsCount": synced_collections_count,
        }))
    }

    async fn sync_wallet_instance_collections(&self) -> Result<usize, TrustCollectionSyncError> {
        let mut count = 0;
        let mut page = 0;
        loop {
            let mut data_to_sync = vec![];
            let wallet_instances = self
                .wallet_instance_repository
                .list(HolderWalletInstanceListQuery {
                    pagination: Some(ListPagination {
                        page,
                        page_size: 1000,
                    }),
                    filtering: Some(
                        Status(WalletInstanceStatus::Active).condition()
                            | Status(WalletInstanceStatus::Unattested),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("listing holder wallet instances")?;
            if wallet_instances.values.is_empty() {
                break;
            }
            for holder_wallet_instance in wallet_instances.values {
                let data = self
                    .fetch_data_for_holder_wallet_instance(holder_wallet_instance)
                    .await?;
                data_to_sync.push(data);
            }
            count += self.sync_collections(data_to_sync).await?;
            page += 1;
        }
        Ok(count)
    }

    async fn sync_verifier_instance_collections(&self) -> Result<usize, TrustCollectionSyncError> {
        let mut count = 0;
        let mut page = 0;
        loop {
            let mut data_to_sync = vec![];
            let verifier_instances = self
                .verifier_instance_repository
                .list(VerifierInstanceListQuery {
                    pagination: Some(ListPagination {
                        page,
                        page_size: 1000,
                    }),
                    ..Default::default()
                })
                .await
                .error_while("listing verifier instances")?;
            if verifier_instances.values.is_empty() {
                break;
            }
            for verifier_instance in verifier_instances.values {
                let data = self
                    .fetch_data_for_verifier_instance(verifier_instance)
                    .await?;
                data_to_sync.push(data);
            }
            count += self.sync_collections(data_to_sync).await?;
            page += 1;
        }
        Ok(count)
    }

    async fn sync_collections(
        &self,
        data_to_sync: Vec<RemoteCollectionData>,
    ) -> Result<usize, TrustCollectionSyncError> {
        let mut count = 0;
        for RemoteCollectionData {
            organisation_id,
            provider_url,
            remote_collections,
        } in data_to_sync
        {
            let synced_collections = self
                .trust_collection_sync
                .sync_remote_trust_collections(&provider_url, remote_collections, organisation_id)
                .await
                .error_while("syncing trust collections")?;

            let collections = self
                .trust_collection_repository
                .list(TrustCollectionListQuery {
                    filtering: Some(
                        TrustCollectionFilterValue::OrganisationId {
                            id: organisation_id,
                            // Parent organisation must not be modified, hence not synced
                            include_inherited_collections: false,
                        }.condition()
                            & TrustCollectionFilterValue::Ids(synced_collections)
                            & TrustCollectionFilterValue::Remote(true)
                            // Empty collections are not enabled and hence should not be synced
                            // (which fills in the trust list subscriptions)
                            & TrustCollectionFilterValue::Empty(false),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("listing trust collections")?;

            for collection in &collections.values {
                self.subscription_sync
                    .sync_subscriptions(collection)
                    .await
                    .error_while("syncing subscriptions")?;
            }
            count += collections.values.len();
        }
        Ok(count)
    }

    async fn fetch_data_for_verifier_instance(
        &self,
        verifier_instance: VerifierInstance,
    ) -> Result<RemoteCollectionData, TrustCollectionSyncError> {
        let metadata_url = format!(
            "{}/ssi/verifier-provider/v1/{}",
            verifier_instance.provider_url, verifier_instance.provider_name
        );
        let metadata = self
            .verifier_client
            .get_verifier_provider_metadata(&metadata_url)
            .await
            .error_while("getting verifier provider metadata")?;
        Ok(RemoteCollectionData {
            organisation_id: verifier_instance.organisation.id(),
            provider_url: verifier_instance.provider_url,
            remote_collections: convert_inner(metadata.trust_collections),
        })
    }

    async fn fetch_data_for_holder_wallet_instance(
        &self,
        holder_wallet_unit: HolderWalletInstance,
    ) -> Result<RemoteCollectionData, TrustCollectionSyncError> {
        let metadata = self
            .wallet_unit_client
            .get_wallet_provider_metadata(holder_wallet_unit.to_owned().into())
            .await
            .error_while("getting wallet provider metadata")?;
        Ok(RemoteCollectionData {
            organisation_id: holder_wallet_unit.organisation.id(),
            provider_url: holder_wallet_unit.wallet_provider_url,
            remote_collections: convert_inner(metadata.trust_collections),
        })
    }
}
