use std::sync::Arc;

use HistoryAction::WrpAcReceived;
use shared_types::{CredentialId, EntityId};

use crate::error::ContextWithErrorCode;
use crate::model::common::SortDirection;
use crate::model::history::HistoryAction::{WrpNrReceived, WrpRcReceived};
use crate::model::history::{
    GetHistoryList, History, HistoryAction, HistoryFilterValue, HistoryListQuery, HistoryMetadata,
    SortableHistoryColumn,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListSorting;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::trust_information::dto::TrustInformationDTO;
use crate::proto::trust_information::{Error, TrustDetails, TrustInformationProvider};
use crate::provider::blob_storage_provider::{BlobStorage, BlobStorageProvider, BlobStorageType};
use crate::provider::signer::registration_certificate::model::Payload;
use crate::repository::history_repository::HistoryRepository;
use crate::service::error::MissingProviderError;
use crate::util::access_cert_parser::{EtsiParsedAccessCert, etsi_access_cert_from_pem_chain};

pub(crate) struct TrustInformationProviderImpl {
    history_repository: Arc<dyn HistoryRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
}

impl TrustInformationProviderImpl {
    pub(crate) fn new(
        history_repository: Arc<dyn HistoryRepository>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
    ) -> Self {
        Self {
            history_repository,
            blob_storage_provider,
        }
    }

    async fn get_wrp_history_entries(
        &self,
        entity_id: impl Into<EntityId>,
        actions: Vec<HistoryAction>,
    ) -> Result<GetHistoryList, Error> {
        self.history_repository
            .get_history_list(HistoryListQuery {
                filtering: Some(
                    HistoryFilterValue::EntityIds(vec![entity_id.into()]).condition()
                        & HistoryFilterValue::Actions(actions),
                ),
                sorting: Some(ListSorting {
                    column: SortableHistoryColumn::CreatedDate,
                    direction: Some(SortDirection::Descending),
                }),
                ..Default::default()
            })
            .await
            .error_while("getting history list")
            .map_err(Into::into)
    }

    async fn parsed_access_cert_from_history(
        &self,
        id: &EntityId,
        history: &GetHistoryList,
        blob_storage: &dyn BlobStorage,
    ) -> Result<EtsiParsedAccessCert, Error> {
        let access_cert_history = history
            .values
            .iter()
            .find(|h| h.action == WrpAcReceived)
            .ok_or(Error::MappingError(format!(
                "Missing access certificate for entity {id}"
            )))?;
        let access_cert_blob_id =
            access_cert_history
                .metadata_blob_id
                .ok_or(Error::MappingError(format!(
                    "Missing blob id on history entry {}",
                    access_cert_history.id
                )))?;
        let access_cert = blob_storage
            .get(&access_cert_blob_id)
            .await
            .error_while("loading access certificate")?
            .ok_or(Error::MappingError(format!(
                "Access certificate blob {access_cert_blob_id} not found"
            )))?;
        let access_certificate =
            etsi_access_cert_from_pem_chain(str::from_utf8(&access_cert.value).map_err(|e| {
                Error::MappingError(format!("failed to parse access certificate blob: {e}"))
            })?)
            .error_while("parsing access certificate")?;

        Ok(access_certificate)
    }

    async fn parsed_registration_cert_from_history(
        &self,
        id: &EntityId,
        history: &GetHistoryList,
        blob_storage: &dyn BlobStorage,
    ) -> Result<JWTPayload<Payload>, Error> {
        let reg_cert_history = history
            .values
            .iter()
            .find(|h| h.action == WrpRcReceived || h.action == WrpNrReceived)
            .ok_or(Error::MappingError(format!(
                "Missing registration certificate for entity {id}"
            )))?;

        let reg_cert_blob_id = reg_cert_history
            .metadata_blob_id
            .ok_or(Error::MappingError(format!(
                "Missing blob id on history entry {}",
                reg_cert_history.id
            )))?;
        let reg_cert = blob_storage
            .get(&reg_cert_blob_id)
            .await
            .error_while("loading registration certificate")?
            .ok_or(Error::MappingError(format!(
                "Registration certificate blob {reg_cert_blob_id} not found"
            )))?;
        let reg_cert = str::from_utf8(&reg_cert.value).map_err(|e| {
            Error::MappingError(format!(
                "failed to parse registration certificate blob: {e}"
            ))
        })?;
        let reg_cert_payload =
            Jwt::decompose_token(reg_cert).error_while("parsing registration certificate")?;
        Ok(reg_cert_payload.payload)
    }
}

#[async_trait::async_trait]
impl TrustInformationProvider for TrustInformationProviderImpl {
    async fn get_trust_information_by_credential_id(
        &self,
        credential_id: CredentialId,
    ) -> Result<Option<TrustInformationDTO>, Error> {
        self.get_wrp_history_entries(credential_id, vec![WrpRcReceived, WrpNrReceived])
            .await?
            .values
            .first()
            .map(History::trust_information)
            .transpose()
    }

    async fn get_trust_detail(&self, id: &EntityId) -> Result<Option<TrustDetails>, Error> {
        // TODO ONE-9430: Properly handle WrpNrReceived
        let history = self
            .get_wrp_history_entries(id, vec![WrpRcReceived, WrpAcReceived])
            .await?;
        if history.values.is_empty() {
            // No trust info
            return Ok(None);
        }
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
            .error_while("getting blob storage")?;
        let access_certificate = self
            .parsed_access_cert_from_history(id, &history, &*blob_storage)
            .await?;
        let registration_certificate = self
            .parsed_registration_cert_from_history(id, &history, &*blob_storage)
            .await?;
        Ok(Some(TrustDetails::Etsi {
            registration_certificate,
            access_certificate,
        }))
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
