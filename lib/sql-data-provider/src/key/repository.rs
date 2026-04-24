use autometrics::autometrics;
use one_core::model::common::GetListResponse;
use one_core::model::key::{GetKeyList, Key, KeyListQuery};
use one_core::repository::error::DataLayerError;
use one_core::repository::key_repository::KeyRepository;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use shared_types::KeyId;

use crate::common::list_query_with_base_model;
use crate::entity::key;
use crate::key::KeyProvider;
use crate::key::mapper::key_from_model;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl KeyRepository for KeyProvider {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError> {
        key::ActiveModel {
            id: Set(request.id),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            name: Set(request.name),
            public_key: Set(request.public_key),
            key_reference: Set(request.key_reference),
            storage_type: Set(request.storage_type),
            key_type: Set(request.key_type),
            organisation_id: Set(request.organisation.id()),
            deleted_at: NotSet,
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(request.id)
    }

    async fn get_key(&self, id: &KeyId) -> Result<Option<Key>, DataLayerError> {
        let key = key::Entity::find_by_id(*id)
            .filter(key::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(|e| {
                tracing::error!("Error while fetching key {}. Error: {}", id, e.to_string());
                DataLayerError::Db(e.into())
            })?;

        let Some(key) = key else {
            return Ok(None);
        };

        Ok(Some(key_from_model(key, &self.organisation_repository)))
    }

    async fn get_keys(&self, ids: &[KeyId]) -> Result<Vec<Key>, DataLayerError> {
        let keys = key::Entity::find()
            .filter(key::Column::DeletedAt.is_null())
            .filter(key::Column::Id.is_in(ids.iter().map(ToString::to_string)))
            .all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!("Error while fetching keys. Error: {}", e.to_string());
                DataLayerError::Db(e.into())
            })?;

        Ok(keys
            .into_iter()
            .map(|key| key_from_model(key, &self.organisation_repository))
            .collect())
    }

    async fn get_key_list(&self, query_params: KeyListQuery) -> Result<GetKeyList, DataLayerError> {
        let query = key::Entity::find()
            .filter(key::Column::DeletedAt.is_null())
            .with_list_query(&query_params)
            .order_by_desc(key::Column::CreatedDate)
            .order_by_desc(key::Column::Id);

        let list: GetListResponse<key::Model> =
            list_query_with_base_model(query, query_params, &self.db).await?;

        Ok(GetKeyList {
            total_items: list.total_items,
            total_pages: list.total_pages,
            values: list
                .values
                .into_iter()
                .map(|key| key_from_model(key, &self.organisation_repository))
                .collect(),
        })
    }
}
