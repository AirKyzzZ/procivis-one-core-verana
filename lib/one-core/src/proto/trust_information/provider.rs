use std::str::FromStr;
use std::sync::Arc;

use HistoryAction::WrpAcReceived;
use dcql::CredentialQueryId;
use shared_types::i18n::I18nString;
use shared_types::{CredentialId, EntityId};

use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::common::SortDirection;
use crate::model::history::HistoryAction::{TrustResolved, WrpNrReceived, WrpRcReceived};
use crate::model::history::{
    GetHistoryList, History, HistoryAction, HistoryFilterValue, HistoryListQuery, HistoryMetadata,
    SortableHistoryColumn, TrustResolutionResult,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListSorting;
use crate::model::verana_trust::VeranaTrustSummary;
use crate::proto::jwt::Jwt;
use crate::proto::trust_information::dto::{
    TrustInformation, TrustPurpose, WalletRelyingPartyDetails,
};
use crate::proto::trust_information::{Error, TrustDetails, TrustInformationProvider};
use crate::proto::verana_trust::VeranaTrustResolver;
use crate::provider::blob_storage::BlobStorage;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::util::access_cert_parser::{EtsiParsedAccessCert, etsi_access_cert_from_pem_chain};

pub(crate) struct TrustInformationProviderImpl {
    history_repository: Arc<dyn HistoryRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    verana_trust_resolver: Option<Arc<VeranaTrustResolver>>,
}

impl TrustInformationProviderImpl {
    #[cfg(any(test, feature = "mock"))]
    pub(crate) fn new(
        history_repository: Arc<dyn HistoryRepository>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
    ) -> Self {
        Self {
            history_repository,
            blob_storage_provider,
            verana_trust_resolver: None,
        }
    }

    pub(crate) fn new_with_verana(
        history_repository: Arc<dyn HistoryRepository>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        verana_trust_resolver: Option<Arc<VeranaTrustResolver>>,
    ) -> Self {
        Self {
            history_repository,
            blob_storage_provider,
            verana_trust_resolver,
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

    async fn parsed_wrp_info_from_history(
        &self,
        id: &EntityId,
        history: &GetHistoryList,
        blob_storage: &dyn BlobStorage,
    ) -> Result<WalletRelyingPartyDetails, Error> {
        let reg_cert_history = history
            .values
            .iter()
            .find(|h| h.action == WrpRcReceived || h.action == WrpNrReceived)
            .ok_or(Error::MappingError(format!(
                "Missing registration certificate for entity {id}"
            )))?;
        let blob_id = reg_cert_history
            .metadata_blob_id
            .ok_or(Error::MappingError(format!(
                "Missing blob id on history entry {}",
                reg_cert_history.id
            )))?;
        let blob = blob_storage
            .get(&blob_id)
            .await
            .error_while("loading registration certificate")?
            .ok_or(Error::MappingError(format!(
                "Registration certificate blob {blob_id} not found"
            )))?;
        let blob_value = str::from_utf8(&blob.value)
            .map_err(|e| Error::MappingError(format!("failed to parse blob value: {e}")))?;
        match reg_cert_history.action {
            WrpRcReceived => {
                let parsed_token = Jwt::decompose_token(blob_value)
                    .error_while("parsing registration certificate")?;
                Ok(WalletRelyingPartyDetails::RegistrationCertificate(
                    parsed_token.payload,
                ))
            }
            WrpNrReceived => {
                let parsed_token = Jwt::decompose_token(blob_value)
                    .error_while("parsing national registry wrp info")?;
                Ok(WalletRelyingPartyDetails::NationalRegistryInfo(
                    parsed_token.payload,
                ))
            }
            action => Err(Error::MappingError(format!(
                "Unexpected history action: {action:?}"
            ))),
        }
    }
}

#[async_trait::async_trait]
impl TrustInformationProvider for TrustInformationProviderImpl {
    async fn get_trust_information(
        &self,
        entity_id: EntityId,
    ) -> Result<Vec<TrustInformation>, Error> {
        let entries = self
            .get_wrp_history_entries(entity_id, vec![WrpRcReceived, WrpNrReceived, TrustResolved])
            .await?
            .values;
        trust_information_from_history(&entries)
    }

    async fn get_trust_purpose(
        &self,
        entity_id: EntityId,
        query_id: &CredentialQueryId,
    ) -> Result<Option<TrustPurpose>, Error> {
        self.get_wrp_history_entries(entity_id, vec![WrpRcReceived, WrpNrReceived])
            .await?
            .values
            .into_iter()
            .nth(0)
            .and_then(|h| trust_purpose_from_history(h, query_id).transpose())
            .transpose()
    }

    async fn get_trust_detail(&self, id: &EntityId) -> Result<Option<TrustDetails>, Error> {
        let history = self
            .get_wrp_history_entries(
                *id,
                vec![WrpRcReceived, WrpNrReceived, WrpAcReceived, TrustResolved],
            )
            .await?;
        if history.values.is_empty() {
            // No trust info
            return Ok(None);
        }
        if let Some(summary) = latest_verana_summary(&history.values) {
            let resolver = self.verana_trust_resolver.as_ref().ok_or_else(|| {
                Error::MappingError("Verana resolver is not configured".to_string())
            })?;
            let full = resolver
                .resolve_full(&summary)
                .await
                .map_err(|error| Error::MappingError(error.to_string()))?;
            return Ok(Some(TrustDetails::Verana(full)));
        }
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        let access_certificate = self
            .parsed_access_cert_from_history(id, &history, &*blob_storage)
            .await?;
        let wrp = self
            .parsed_wrp_info_from_history(id, &history, &*blob_storage)
            .await?;
        Ok(Some(TrustDetails::Etsi {
            wrp,
            access_certificate,
        }))
    }
}

fn trust_information_from_history(history: &[History]) -> Result<Vec<TrustInformation>, Error> {
    let name = history
        .iter()
        .find(|h| h.action == WrpRcReceived || h.action == WrpNrReceived)
        .map(wrp_name_from_history)
        .transpose()?;
    let mut entries = vec![];
    for h in history.iter().filter(|h| h.action == TrustResolved) {
        let (result, verana) = trust_resolution_from_history_metadata(h)?;
        let credential_id = if let Some(target) = &h.target {
            Some(CredentialId::from_str(target).map_err(|err| {
                Error::MappingError(format!(
                    "invalid credential id `{target}` set as TRUST_RESOLVED target: {err}"
                ))
            })?)
        } else {
            None
        };
        entries.push(TrustInformation {
            received_at: h.created_date,
            name: name.clone(),
            result,
            verana,
            credential_id,
        });
    }
    Ok(entries)
}

fn wrp_name_from_history(history: &History) -> Result<String, Error> {
    let metadata = history.metadata.as_ref().ok_or_else(|| {
        Error::MissingHistoryMetadata(
            history.id,
            history.entity_type,
            history.entity_id,
            history.action,
        )
    })?;
    match metadata {
        HistoryMetadata::WalletRelyingParty(metadata) => Ok(metadata.name.to_owned()),
        _ => Err(Error::InvalidMetadataType(
            metadata.into(),
            "WalletRelyingParty",
        )),
    }
}

fn trust_resolution_from_history_metadata(
    history: &History,
) -> Result<(TrustResolutionResult, Option<VeranaTrustSummary>), Error> {
    let metadata = history.metadata.as_ref().ok_or_else(|| {
        Error::MissingHistoryMetadata(
            history.id,
            history.entity_type,
            history.entity_id,
            history.action,
        )
    })?;
    match metadata {
        HistoryMetadata::TrustResolution(metadata) => {
            Ok((metadata.result, metadata.verana.clone()))
        }
        _ => Err(Error::InvalidMetadataType(
            metadata.into(),
            "WalletRelyingParty",
        )),
    }
}

fn latest_verana_summary(history: &[History]) -> Option<VeranaTrustSummary> {
    history.iter().find_map(|history| match &history.metadata {
        Some(HistoryMetadata::TrustResolution(metadata)) => metadata.verana.clone(),
        _ => None,
    })
}

fn trust_purpose_from_history(
    history: History,
    query_id: &CredentialQueryId,
) -> Result<Option<TrustPurpose>, Error> {
    history
        .metadata
        .ok_or_else(|| {
            Error::MissingHistoryMetadata(
                history.id,
                history.entity_type,
                history.entity_id,
                history.action,
            )
        })
        .and_then(|hm| trust_purpose_from_history_metadata(hm, query_id))
}

fn trust_purpose_from_history_metadata(
    history_metadata: HistoryMetadata,
    query_id: &CredentialQueryId,
) -> Result<Option<TrustPurpose>, Error> {
    match history_metadata {
        HistoryMetadata::WalletRelyingParty(mut metadata) => Ok(metadata
            .purpose
            .remove(query_id)
            .map(|purpose| TrustPurpose {
                purpose: I18nString(purpose.into_iter().map(|p| (p.lang, p.value)).collect()),
            })),
        _ => Err(Error::InvalidMetadataType(
            history_metadata.into(),
            "WalletRelyingParty",
        )),
    }
}
