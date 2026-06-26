use std::sync::Arc;

use anyhow::Context;
use shared_types::{DidId, DidValue, OrganisationId};
use uuid::Uuid;

use crate::model::did::{Did, DidListQuery, GetDidList, UpdateDidRequest};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;

pub struct DidHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn DidRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

impl DidHistoryDecorator {
    async fn create_history(
        &self,
        id: DidId,
        name: String,
        action: HistoryAction,
        organisation: Option<&Related<Organisation>>,
    ) {
        let Some(organisation_id) = organisation.map(|o| o.id()) else {
            tracing::warn!("did (id: {id}) missing organisation");
            return;
        };

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action,
                name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Did,
                metadata: None,
                metadata_blob_id: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(error) = result {
            tracing::warn!(%error, "failed to insert did history event");
        }
    }
}

#[async_trait::async_trait]
impl DidRepository for DidHistoryDecorator {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        let name = request.name.clone();
        let organisation = request.organisation.to_owned();
        let did_id = self.inner.create_did(request).await?;

        self.create_history(did_id, name, HistoryAction::Created, organisation.as_ref())
            .await;

        Ok(did_id)
    }

    async fn get_did(&self, id: &DidId) -> Result<Option<Did>, DataLayerError> {
        self.inner.get_did(id).await
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        organisation: Option<Option<OrganisationId>>,
    ) -> Result<Option<Did>, DataLayerError> {
        self.inner.get_did_by_value(value, organisation).await
    }

    async fn get_did_list(&self, query: DidListQuery) -> Result<GetDidList, DataLayerError> {
        self.inner.get_did_list(query).await
    }

    async fn update_did(&self, request: UpdateDidRequest) -> Result<(), DataLayerError> {
        self.inner.update_did(request.clone()).await?;

        if let Some(deactivated) = request.deactivated {
            let did = self
                .inner
                .get_did(&request.id)
                .await?
                .context("did is missing")?;

            self.create_history(
                did.id,
                did.name,
                if deactivated {
                    HistoryAction::Deactivated
                } else {
                    HistoryAction::Reactivated
                },
                did.organisation.as_ref(),
            )
            .await;
        };

        Ok(())
    }

    async fn delete_did(&self, did: &Did) -> Result<(), DataLayerError> {
        self.inner.delete_did(did).await?;
        self.create_history(
            did.id,
            did.name.clone(),
            HistoryAction::Deleted,
            did.organisation.as_ref(),
        )
        .await;
        Ok(())
    }
}
