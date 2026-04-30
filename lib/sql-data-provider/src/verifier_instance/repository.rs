use async_trait::async_trait;
use one_core::model::verifier_instance::{
    GetVerifierInstanceList, UpdateVerifierInstanceRequest, VerifierInstance,
    VerifierInstanceListQuery,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::verifier_instance_repository::VerifierInstanceRepository;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set, Unchanged};
use shared_types::VerifierInstanceId;

use super::VerifierInstanceProvider;
use crate::common::list_query_with_custom_model;
use crate::entity::verifier_instance;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::verifier_instance::mapper::verifier_instance_from_model;

#[async_trait]
impl VerifierInstanceRepository for VerifierInstanceProvider {
    async fn create(
        &self,
        request: VerifierInstance,
    ) -> Result<VerifierInstanceId, DataLayerError> {
        let model = verifier_instance::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(model.id)
    }

    async fn update(
        &self,
        id: &VerifierInstanceId,
        request: UpdateVerifierInstanceRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = verifier_instance::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
            trusted_issuer_required: request.trusted_issuer_required.map(Set).unwrap_or_default(),
            ..Default::default()
        };
        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get(
        &self,
        id: &VerifierInstanceId,
    ) -> Result<Option<VerifierInstance>, DataLayerError> {
        let model = verifier_instance::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        let Some(model) = model else { return Ok(None) };

        Ok(Some(verifier_instance_from_model(
            model,
            &self.organisation_repository,
        )))
    }

    async fn list(
        &self,
        query_params: VerifierInstanceListQuery,
    ) -> Result<GetVerifierInstanceList, DataLayerError> {
        let query = verifier_instance::Entity::find()
            .with_list_query(&query_params)
            .order_by_desc(verifier_instance::Column::CreatedDate)
            .order_by_desc(verifier_instance::Column::Id);

        list_query_with_custom_model(query, query_params, &self.db, |m| {
            Ok(verifier_instance_from_model(
                m,
                &self.organisation_repository,
            ))
        })
        .await
    }
}
