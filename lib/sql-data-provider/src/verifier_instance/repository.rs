use async_trait::async_trait;
use one_core::model::verifier_instance::VerifierInstance;
use one_core::repository::error::DataLayerError;
use one_core::repository::verifier_instance_repository::VerifierInstanceRepository;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use shared_types::{OrganisationId, VerifierInstanceId};

use super::VerifierInstanceProvider;
use crate::entity::verifier_instance;
use crate::mapper::to_data_layer_error;
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

    async fn get_by_org_id(
        &self,
        organisation_id: &OrganisationId,
    ) -> Result<Option<VerifierInstance>, DataLayerError> {
        let model = verifier_instance::Entity::find()
            .filter(verifier_instance::Column::OrganisationId.eq(organisation_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(model.map(|m| verifier_instance_from_model(m, &self.organisation_repository)))
    }
}
