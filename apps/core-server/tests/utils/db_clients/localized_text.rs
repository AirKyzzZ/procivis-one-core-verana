use std::sync::Arc;

use one_core::model::localized_text::LocalizedText;
use one_core::repository::localized_text_repository::LocalizedTextRepository;
use shared_types::EntityId;

pub struct LocalizedTextDB {
    repository: Arc<dyn LocalizedTextRepository>,
}

impl LocalizedTextDB {
    pub fn new(repository: Arc<dyn LocalizedTextRepository>) -> Self {
        Self { repository }
    }

    #[allow(unused)]
    pub async fn upsert(&self, text: LocalizedText) {
        self.repository.upsert(text).await.unwrap();
    }

    pub async fn get(&self, id: impl Into<EntityId>) -> Vec<LocalizedText> {
        self.repository.get(&id.into()).await.unwrap()
    }
}
