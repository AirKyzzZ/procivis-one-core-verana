use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use shared_types::{KeyId, OrganisationId, TrustCollectionId};

use super::dto::{HolderWalletInstanceResponseDTO, TrustCollectionInfoDTO};
use super::error::HolderWalletInstanceError;
use crate::error::ContextWithErrorCode;
use crate::model::holder_wallet_instance::HolderWalletInstance;
use crate::model::key::Key;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::Organisation;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::model::trust_list_subscription::{
    TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery, TrustListSubscriptionState,
};
use crate::model::wallet_instance::WalletInstanceStatus;
use crate::proto::trust_collection::dto::RemoteTrustCollectionInfoDTO;
use crate::proto::trust_list_subscription_sync::TrustListSubscriptionSync;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::wallet_provider::dto::ProviderTrustCollectionDTO;

pub(super) fn key_from_generated_key(
    key_id: KeyId,
    key_storage_id: &str,
    key_type: &str,
    organisation: Organisation,
    generated_key: StorageGeneratedKey,
) -> Key {
    let now = crate::clock::now_utc();

    Key {
        id: key_id,
        created_date: now,
        last_modified: now,
        public_key: generated_key.public_key,
        name: format!("Wallet unit key {key_id}"),
        key_reference: generated_key.key_reference,
        storage_type: key_storage_id.to_string(),
        key_type: key_type.to_string(),
        organisation: organisation.into(),
    }
}

impl From<HolderWalletInstance> for HolderWalletInstanceResponseDTO {
    fn from(value: HolderWalletInstance) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            provider_wallet_unit_id: value.provider_wallet_unit_id,
            wallet_provider_url: value.wallet_provider_url,
            wallet_provider_type: value.wallet_provider_type,
            wallet_provider_name: value.wallet_provider_name,
            status: value.status,
            authentication_key: convert_inner(value.authentication_key),
            trusted_rp_required: value.trusted_rp_required,
            user_nonce: (value.status == WalletInstanceStatus::Pending)
                .then_some(value.user_nonce)
                .flatten(),
        }
    }
}

impl From<ProviderTrustCollectionDTO> for RemoteTrustCollectionInfoDTO {
    fn from(value: ProviderTrustCollectionDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

pub(crate) async fn prepare_trust_collection_info(
    trust_collection_repository: &dyn TrustCollectionRepository,
    trust_subscription_repository: &dyn TrustListSubscriptionRepository,
    provider_metadata_trust_collections: Vec<ProviderTrustCollectionDTO>,
    organisation_id: OrganisationId,
) -> Result<Vec<TrustCollectionInfoDTO>, HolderWalletInstanceError> {
    let local_trust_collections = trust_collection_repository
        .list(TrustCollectionListQuery {
            filtering: Some(
                TrustCollectionFilterValue::OrganisationId {
                    id: organisation_id,
                    include_inherited_collections: false,
                }
                .condition(),
            ),
            ..Default::default()
        })
        .await
        .error_while("getting local trust collections")?
        .values;

    let mut local_id_to_metadata = HashMap::<TrustCollectionId, ProviderTrustCollectionDTO>::new();
    for metadata_collection in provider_metadata_trust_collections {
        let local_collection = local_trust_collections
            .iter()
            .find(|lc| lc.name == metadata_collection.name)
            .ok_or(HolderWalletInstanceError::TrustCollectionsNotInSync)?;
        if local_collection.remote_trust_collection_url.is_none() {
            // There is a local collection with the same name (which we prefer over remote ones).
            // Hence this collection should be skipped and not shown as a selection option.
            continue;
        }

        local_id_to_metadata.insert(local_collection.id, metadata_collection);
    }

    let mut collections_with_subscription_state = vec![];
    for (id, metadata) in local_id_to_metadata {
        let subscriptions = trust_subscription_repository
            .list(TrustListSubscriptionListQuery {
                filtering: Some(
                    TrustListSubscriptionFilterValue::TrustCollectionId(vec![id]).condition()
                        & TrustListSubscriptionFilterValue::State(vec![
                            TrustListSubscriptionState::Active,
                        ]),
                ),
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 1,
                }),
                ..Default::default()
            })
            .await
            .error_while("listing subscriptions")?;

        collections_with_subscription_state.push((id, metadata, subscriptions.total_items > 0));
    }

    // When no collection has an active subscription yet, the user has not made a selection;
    // in that case the provider-configured `defaultSelected` flag determines the selection.
    let any_subscription_exists = collections_with_subscription_state
        .iter()
        .any(|(_, _, has_subscription)| *has_subscription);

    Ok(collections_with_subscription_state
        .into_iter()
        .map(|(id, metadata, has_subscription)| {
            let selected = if any_subscription_exists {
                has_subscription
            } else {
                metadata.default_selected.unwrap_or(false)
            };
            TrustCollectionInfoDTO {
                selected,
                collection: ProviderTrustCollectionDTO { id, ..metadata },
            }
        })
        .collect())
}

pub(crate) async fn set_active_trust_collections(
    trust_collections: Vec<TrustCollectionId>,
    organisation_id: OrganisationId,
    trust_collection_repository: &dyn TrustCollectionRepository,
    trust_subscription_repository: &dyn TrustListSubscriptionRepository,
    trust_list_subscription_sync: &dyn TrustListSubscriptionSync,
) -> Result<(), HolderWalletInstanceError> {
    let all_trust_collections = trust_collection_repository
        .list(TrustCollectionListQuery {
            filtering: Some(
                TrustCollectionFilterValue::OrganisationId {
                    id: organisation_id,
                    include_inherited_collections: false,
                }
                .condition(),
            ),
            ..Default::default()
        })
        .await
        .error_while("getting trust collections")?
        .values;

    let collections_to_remove = all_trust_collections
        .iter()
        .filter(|c| !trust_collections.contains(&c.id))
        .map(|c| c.id);

    let mut subscriptions_to_remove = vec![];
    for collection_id in collections_to_remove {
        subscriptions_to_remove.extend(
            trust_subscription_repository
                .list(TrustListSubscriptionListQuery {
                    filtering: Some(
                        TrustListSubscriptionFilterValue::TrustCollectionId(vec![collection_id])
                            .condition(),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("listing subscriptions")?
                .values
                .into_iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
        );
    }

    trust_subscription_repository
        .delete_many(subscriptions_to_remove)
        .await
        .error_while("deleting subscriptions")?;

    for requested in trust_collections {
        let collection = all_trust_collections
            .iter()
            .find(|c| c.id == requested)
            .ok_or(HolderWalletInstanceError::MissingTrustCollection(requested))?;

        trust_list_subscription_sync
            .sync_subscriptions(collection)
            .await
            .error_while("syncing trust collection")?;
    }

    Ok(())
}
