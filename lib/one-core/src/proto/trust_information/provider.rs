use std::sync::Arc;

use shared_types::{CredentialId, EntityId};

use crate::error::ContextWithErrorCode;
use crate::model::common::SortDirection;
use crate::model::history::HistoryAction::{WrpNrReceived, WrpRcReceived};
use crate::model::history::{
    History, HistoryFilterValue, HistoryListQuery, HistoryMetadata, SortableHistoryColumn,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListSorting;
use crate::proto::trust_information::dto::TrustInformationDTO;
use crate::proto::trust_information::{Error, TrustInformationProvider};
use crate::repository::history_repository::HistoryRepository;

pub(crate) struct TrustInformationProviderImpl {
    pub(crate) history_repository: Arc<dyn HistoryRepository>,
}

impl TrustInformationProviderImpl {
    pub(crate) fn new(history_repository: Arc<dyn HistoryRepository>) -> Self {
        Self { history_repository }
    }

    async fn get_latest_wrp_history_entry(
        &self,
        entity_id: impl Into<EntityId>,
    ) -> Result<Option<History>, Error> {
        Ok(self
            .history_repository
            .get_history_list(HistoryListQuery {
                filtering: Some(
                    HistoryFilterValue::EntityIds(vec![entity_id.into()]).condition()
                        & HistoryFilterValue::Actions(vec![WrpRcReceived, WrpNrReceived]),
                ),
                sorting: Some(ListSorting {
                    column: SortableHistoryColumn::CreatedDate,
                    direction: Some(SortDirection::Descending),
                }),
                ..Default::default()
            })
            .await
            .error_while("getting history list")?
            .values
            .into_iter()
            .nth(0))
    }
}

#[async_trait::async_trait]
impl TrustInformationProvider for TrustInformationProviderImpl {
    async fn get_trust_information_by_credential_id(
        &self,
        credential_id: CredentialId,
    ) -> Result<Option<TrustInformationDTO>, Error> {
        self.get_latest_wrp_history_entry(credential_id)
            .await?
            .as_ref()
            .map(History::trust_information)
            .transpose()
    }
}

impl History {
    fn trust_information(&self) -> Result<TrustInformationDTO, Error> {
        self.metadata
            .as_ref()
            .ok_or_else(|| Error::MissingHistoryMetadata(self.id, self.action))
            .and_then(extract_rp_name_metadata)
            .map(|name| TrustInformationDTO {
                received_at: self.created_date,
                name,
            })
    }
}

fn extract_rp_name_metadata(metadata: &HistoryMetadata) -> Result<String, Error> {
    match metadata {
        HistoryMetadata::WalletRelayingParty(metadata) => Ok(metadata.name.clone()),
        _ => Err(Error::InvalidMetadataType(
            metadata.into(),
            "WalletRelayingParty",
        )),
    }
}
