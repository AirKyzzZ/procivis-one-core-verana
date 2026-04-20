use async_trait::async_trait;
use one_core::model::revocation_list::RevocationListRelations;
use one_core::model::wallet_instance_attested_key::{
    WalletInstanceAttestedKey, WalletInstanceAttestedKeyRelations,
    WalletInstanceAttestedKeyRevocationInfo, WalletInstanceAttestedKeyUpsertRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_instance_attested_key_repository::WalletInstanceAttestedKeyRepository;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryTrait, Set,
    Unchanged,
};
use shared_types::{WalletInstanceAttestedKeyId, WalletInstanceId};

use crate::entity::{revocation_list_entry, wallet_instance_attested_key};
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::wallet_instance_attested_key::WalletInstanceAttestedKeyProvider;

#[async_trait]
impl WalletInstanceAttestedKeyRepository for WalletInstanceAttestedKeyProvider {
    async fn create_attested_key(
        &self,
        request: WalletInstanceAttestedKey,
    ) -> Result<WalletInstanceAttestedKeyId, DataLayerError> {
        let model: wallet_instance_attested_key::ActiveModel = request.try_into()?;
        let result = model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(result.id)
    }

    async fn update_attested_key(
        &self,
        request: WalletInstanceAttestedKey,
    ) -> Result<(), DataLayerError> {
        let id = request.id;
        let mut model = wallet_instance_attested_key::ActiveModel::try_from(request)?;
        model.id = Unchanged(id);
        model.last_modified = Set(one_core::clock::now_utc());
        wallet_instance_attested_key::Entity::update(model)
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn upsert_attested_key(
        &self,
        request: WalletInstanceAttestedKeyUpsertRequest,
    ) -> Result<WalletInstanceAttestedKeyId, DataLayerError> {
        let id = request.id;
        let model = wallet_instance_attested_key::ActiveModel::try_from(request)?;
        let stmt = wallet_instance_attested_key::Entity::insert(model)
            .on_conflict(
                OnConflict::column(wallet_instance_attested_key::Column::Id)
                    .update_column(wallet_instance_attested_key::Column::LastModified)
                    .update_column(wallet_instance_attested_key::Column::ExpirationDate)
                    .update_column(wallet_instance_attested_key::Column::PublicKeyJwk)
                    .update_column(wallet_instance_attested_key::Column::WalletInstanceId)
                    .to_owned(),
            )
            .build(self.db.get_database_backend());
        self.db
            .execute(stmt)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(id)
    }

    async fn get_attested_key(
        &self,
        id: &WalletInstanceAttestedKeyId,
        relations: &WalletInstanceAttestedKeyRelations,
    ) -> Result<Option<WalletInstanceAttestedKey>, DataLayerError> {
        let model = wallet_instance_attested_key::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(match model {
            Some(model) => Some(self.convert_model(model, relations).await?),
            None => None,
        })
    }

    async fn get_by_wallet_instance_id(
        &self,
        id: &WalletInstanceId,
        relations: &WalletInstanceAttestedKeyRelations,
    ) -> Result<Vec<WalletInstanceAttestedKey>, DataLayerError> {
        let models = wallet_instance_attested_key::Entity::find()
            .filter(wallet_instance_attested_key::Column::WalletInstanceId.eq(id))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let mut results = vec![];
        for model in models {
            results.push(self.convert_model(model, relations).await?);
        }
        Ok(results)
    }
}

impl WalletInstanceAttestedKeyProvider {
    async fn convert_model(
        &self,
        model: wallet_instance_attested_key::Model,
        relations: &WalletInstanceAttestedKeyRelations,
    ) -> Result<WalletInstanceAttestedKey, DataLayerError> {
        let revocation = if let Some(revocation_relations) = &relations.revocation {
            self.get_revocation(&model, revocation_relations).await?
        } else {
            None
        };

        let mut result = WalletInstanceAttestedKey::try_from(model)?;
        result.revocation = revocation;

        Ok(result)
    }

    async fn get_revocation(
        &self,
        model: &wallet_instance_attested_key::Model,
        relations: &RevocationListRelations,
    ) -> Result<Option<WalletInstanceAttestedKeyRevocationInfo>, DataLayerError> {
        let Some(revocation_list_entry_id) = &model.revocation_list_entry_id else {
            return Ok(None);
        };

        let revocation_list_entry =
            revocation_list_entry::Entity::find_by_id(revocation_list_entry_id)
                .one(&self.db)
                .await
                .map_err(to_data_layer_error)?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "wallet_unit_attested_key-revocation_list_entry",
                    id: revocation_list_entry_id.to_string(),
                })?;

        let revocation_list_index =
            revocation_list_entry
                .index
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "wallet_unit_attested_key-revocation_list_entry-index",
                    id: revocation_list_entry_id.to_string(),
                })? as _;

        let revocation_list = self
            .revocation_list_repository
            .get_revocation_list(&revocation_list_entry.revocation_list_id, relations)
            .await?
            .ok_or(DataLayerError::MissingRequiredRelation {
                relation: "wallet_unit_attested_key-revocation_list",
                id: revocation_list_entry.revocation_list_id.to_string(),
            })?;

        Ok(Some(WalletInstanceAttestedKeyRevocationInfo {
            revocation_list,
            revocation_list_index,
        }))
    }
}
