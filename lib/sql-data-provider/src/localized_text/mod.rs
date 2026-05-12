use one_core::model::localized_text::LocalizedText;
use one_core::model::relation::AsyncVecLoader;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use shared_types::EntityId;

use crate::entity::localized_text;
use crate::mapper::to_data_layer_error;
use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;
#[cfg(test)]
mod test;

pub(crate) struct LocalizedTextProvider {
    pub db: TransactionManagerImpl,
}

pub(crate) struct LocalizedTextLoader {
    pub id: EntityId,
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncVecLoader<LocalizedText> for LocalizedTextLoader {
    async fn load(&self) -> Result<Vec<LocalizedText>, DataLayerError> {
        let translations: Vec<localized_text::Model> = localized_text::Entity::find()
            .filter(localized_text::Column::EntityId.eq(self.id.to_string()))
            .order_by_asc(localized_text::Column::CreatedDate)
            .order_by_asc(localized_text::Column::Lang)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(convert_inner(translations))
    }
}
