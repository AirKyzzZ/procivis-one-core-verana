use std::fmt::Debug;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::repository::error::DataLayerError;

pub trait Model {
    type Id: Clone + Debug;
    fn id(&self) -> &Self::Id;
}

// Related model
#[async_trait::async_trait]
pub trait AsyncModelLoader<M: Model>: Send + Sync {
    async fn load(&self, id: &M::Id) -> Result<M, DataLayerError>;
}

#[derive(Clone, Debug)]
pub struct Related<M: Model> {
    id: M::Id,
    data: Arc<Mutex<AsyncModelStore<M>>>,
}

impl<M: Model> Related<M> {
    pub fn new(id: M::Id, loader: impl AsyncModelLoader<M> + 'static) -> Self {
        Self {
            id,
            data: Arc::new(Mutex::new(AsyncModelStore::ToBeLoaded(Box::new(loader)))),
        }
    }

    pub fn id_ref(&self) -> &M::Id {
        &self.id
    }
}

impl<M: Model> Related<M>
where
    M::Id: Copy,
{
    pub fn id(&self) -> M::Id {
        self.id
    }
}

impl<M: Model + Clone> Related<M> {
    pub async fn get(&self) -> Result<M, DataLayerError> {
        let mut guard = self.data.lock().await;
        Ok(match &*guard {
            AsyncModelStore::AlreadyLoaded(data) => data.to_owned(),
            AsyncModelStore::ToBeLoaded(loader) => {
                let data = loader.load(&self.id).await?;
                *guard = AsyncModelStore::AlreadyLoaded(data.to_owned());
                data
            }
        })
    }
}

impl<M: Model> From<M> for Related<M> {
    fn from(model: M) -> Self {
        Self {
            id: model.id().to_owned(),
            data: Arc::new(Mutex::new(AsyncModelStore::AlreadyLoaded(model))),
        }
    }
}

#[cfg(any(test, feature = "mock"))]
impl<M: Model> PartialEq for Related<M>
where
    M::Id: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

// Related models collection
#[async_trait::async_trait]
pub trait AsyncModelsLoader<M: Model>: Send + Sync {
    /// Loads collection of models specified by `ids`
    async fn load(&self, ids: &[M::Id]) -> Result<Vec<M>, DataLayerError>;
}

#[async_trait::async_trait]
pub trait AsyncVecLoader<T>: Send + Sync {
    /// Loads collection of relations
    async fn load(&self) -> Result<Vec<T>, DataLayerError>;
}

#[derive(Clone, Debug)]
pub struct RelatedVec<T> {
    data: Arc<Mutex<AsyncVecStore<T>>>,
}

impl<T> RelatedVec<T> {
    pub fn new(loader: impl AsyncVecLoader<T> + 'static) -> Self {
        Self {
            data: Arc::new(Mutex::new(AsyncVecStore::ToBeLoaded(Box::new(loader)))),
        }
    }
}

impl<T: Clone> RelatedVec<T> {
    pub async fn get(&self) -> Result<Vec<T>, DataLayerError> {
        let mut guard = self.data.lock().await;
        Ok(match &*guard {
            AsyncVecStore::AlreadyLoaded(data) => data.to_owned(),
            AsyncVecStore::ToBeLoaded(loader) => {
                let data = loader.load().await?;
                *guard = AsyncVecStore::AlreadyLoaded(data.to_owned());
                data
            }
        })
    }
}

impl<T> From<Vec<T>> for RelatedVec<T> {
    fn from(models: Vec<T>) -> Self {
        Self {
            data: Arc::new(Mutex::new(AsyncVecStore::AlreadyLoaded(models))),
        }
    }
}

impl<M: Model + 'static> RelatedVec<M>
where
    M::Id: Send + Sync,
{
    pub fn from_ids(
        ids: impl Into<Vec<M::Id>>,
        loader: impl AsyncModelsLoader<M> + 'static,
    ) -> Self {
        Self::new(ModelsLoaderWrapper {
            ids: ids.into(),
            loader: Box::new(loader),
        })
    }
}

impl<T> Default for RelatedVec<T> {
    fn default() -> Self {
        Self::from(Vec::default())
    }
}

#[cfg(any(test, feature = "mock"))]
impl<T> PartialEq for RelatedVec<T> {
    fn eq(&self, _other: &Self) -> bool {
        // skip comparison of related collections in tests
        true
    }
}

// helper implementations
enum AsyncModelStore<M: Model> {
    AlreadyLoaded(M),
    ToBeLoaded(Box<dyn AsyncModelLoader<M>>),
}

impl<T: Model + Debug> Debug for AsyncModelStore<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyLoaded(model) => f.debug_tuple("AlreadyLoaded").field(model).finish(),
            Self::ToBeLoaded(_) => f.debug_tuple("ToBeLoaded").finish(),
        }
    }
}

enum AsyncVecStore<T> {
    AlreadyLoaded(Vec<T>),
    ToBeLoaded(Box<dyn AsyncVecLoader<T>>),
}

impl<T: Debug> Debug for AsyncVecStore<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyLoaded(models) => f.debug_tuple("AlreadyLoaded").field(models).finish(),
            Self::ToBeLoaded(_) => f.debug_tuple("ToBeLoaded").finish(),
        }
    }
}

// AsyncVecLoader wrapper
struct ModelsLoaderWrapper<M: Model> {
    ids: Vec<M::Id>,
    loader: Box<dyn AsyncModelsLoader<M>>,
}

#[async_trait::async_trait]
impl<M: Model> AsyncVecLoader<M> for ModelsLoaderWrapper<M>
where
    M::Id: Send + Sync,
{
    async fn load(&self) -> Result<Vec<M>, DataLayerError> {
        self.loader.load(&self.ids).await
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::model::claim_schema::ClaimSchema;
    use crate::repository::claim_schema_repository::{
        ClaimSchemaRepository, MockClaimSchemaRepository,
    };
    use crate::repository::organisation_repository::{
        MockOrganisationRepository, OrganisationRepository,
    };
    use crate::service::test_utilities::{dummy_claim_schema, dummy_organisation};

    #[tokio::test]
    async fn test_from() {
        let id = Uuid::new_v4().into();
        let data = Related::from(dummy_organisation(Some(id)));
        assert_eq!(data.get().await.unwrap().id, id);

        let claim_schema = dummy_claim_schema();
        let data = RelatedVec::from(vec![claim_schema.clone()]);
        assert_eq!(data.get().await.unwrap(), vec![claim_schema]);
    }

    #[tokio::test]
    async fn test_organisation_repository() {
        let mut repository = MockOrganisationRepository::new();
        repository
            .expect_get_organisation()
            .once()
            .return_once(|id| Ok(Some(dummy_organisation(Some(*id)))));

        let repository: Arc<dyn OrganisationRepository> = Arc::new(repository);

        let id = Uuid::new_v4().into();
        let related = Related::new(id, repository);
        assert_eq!(related.id(), id);
        let organsation = related.get().await.unwrap();
        assert_eq!(organsation.id, id);
    }

    #[tokio::test]
    async fn test_claim_schemas_repository() {
        let mut repository = MockClaimSchemaRepository::new();
        repository
            .expect_get_claim_schema_list()
            .once()
            .return_once(|_| Ok(vec![]));

        let repository: Arc<dyn ClaimSchemaRepository> = Arc::new(repository);

        let id = Uuid::new_v4().into();
        let related: RelatedVec<ClaimSchema> = RelatedVec::from_ids(vec![id], repository);
        let claim_schemas = related.get().await.unwrap();
        assert_eq!(claim_schemas.len(), 0);
    }
}
