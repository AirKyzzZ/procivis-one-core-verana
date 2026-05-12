use std::collections::HashMap;

use autometrics::autometrics;
use itertools::Itertools;
use one_core::model::claim_schema::ClaimSchema;
use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::error::DataLayerError;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use shared_types::ClaimSchemaId;

use super::ClaimSchemaProvider;
use crate::claim_schema::mapper::claim_schema_from_model;
use crate::entity::claim_schema;

#[autometrics]
#[async_trait::async_trait]
impl ClaimSchemaRepository for ClaimSchemaProvider {
    async fn get_claim_schema_list(
        &self,
        ids: Vec<ClaimSchemaId>,
    ) -> Result<Vec<ClaimSchema>, DataLayerError> {
        let claim_schema_cnt = ids.iter().unique().count();
        let claim_schema_to_index: HashMap<ClaimSchemaId, usize> = ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect();

        let claim_schema_ids = claim_schema_to_index.keys().map(ToString::to_string);
        let models = claim_schema::Entity::find()
            .filter(claim_schema::Column::Id.is_in(claim_schema_ids))
            .all(&self.db)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        if claim_schema_cnt != models.len() {
            return Err(DataLayerError::IncompleteClaimsSchemaList {
                expected: claim_schema_cnt,
                got: models.len(),
            });
        }

        let mut claim_schema_list: Vec<ClaimSchema> = models
            .into_iter()
            .map(|cs| claim_schema_from_model(cs, self.db.clone()))
            .collect();

        #[allow(clippy::indexing_slicing)]
        claim_schema_list.sort_by_key(|claim_schema| claim_schema_to_index[&claim_schema.id]);

        Ok(claim_schema_list)
    }
}
