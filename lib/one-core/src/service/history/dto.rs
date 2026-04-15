use one_dto_mapper::{From, convert_inner, convert_inner_of_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{
    CredentialId, CredentialSchemaId, EntityId, HistoryId, IdentifierId, OrganisationId, ProofId,
    ProofSchemaId,
};
use standardized_types::etsi_119_602::MultiLangString;
use time::OffsetDateTime;

use crate::error::ErrorCode;
use crate::model::common::GetListResponse;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata,
    HistorySearchEnum, HistorySource, IntendedUse, WalletRelayingPartyMetadata,
};
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(HistoryMetadata)]
pub enum HistoryMetadataResponse {
    UnexportableEntities(UnexportableEntitiesResponseDTO),
    ErrorMetadata(HistoryErrorMetadataDTO),
    WalletUnitJWT(String),
    External(serde_json::Value),
    WalletRelayingParty(WalletRelayingPartyMetadataDTO),
}

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(HistoryErrorMetadata)]
pub struct HistoryErrorMetadataDTO {
    pub error_code: ErrorCode,
    pub message: String,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(WalletRelayingPartyMetadata)]
pub struct WalletRelayingPartyMetadataDTO {
    pub name: String,
    #[from(with_fn = convert_inner_of_inner)]
    pub intended_use: Option<Vec<IntendedUseDTO>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(IntendedUse)]
pub struct IntendedUseDTO {
    pub format: dcql::CredentialFormat,
    pub meta: dcql::CredentialMeta,
    pub purpose: Vec<MultiLangString>,
}

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(History)]
pub struct HistoryResponseDTO {
    pub created_date: OffsetDateTime,
    pub id: HistoryId,
    pub action: HistoryAction,
    pub name: String,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: Option<OrganisationId>,
    #[from(with_fn = convert_inner)]
    pub metadata: Option<HistoryMetadataResponse>,
    pub source: HistorySource,
    pub target: Option<String>,
    pub user: Option<String>,
}

pub type GetHistoryListResponseDTO = GetListResponse<HistoryResponseDTO>;

#[derive(Clone, Debug, Default)]
pub struct HistoryFilterParamsDTO {
    pub organisation_ids: Option<Vec<OrganisationId>>,
    pub entity_ids: Option<Vec<EntityId>>,
    pub entity_types: Option<Vec<HistoryEntityType>>,
    pub actions: Option<Vec<HistoryAction>>,
    pub identifier_id: Option<IdentifierId>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub credential_id: Option<CredentialId>,
    pub credential_schema_id: Option<CredentialSchemaId>,
    pub proof_id: Option<ProofId>,
    pub proof_schema_id: Option<ProofSchemaId>,
    pub users: Option<Vec<String>>,
    pub sources: Option<Vec<HistorySource>>,
    pub search_query: Option<String>,
    pub search_type: Option<HistorySearchEnum>,
}

#[derive(Debug, Clone)]
pub struct CreateHistoryRequestDTO {
    pub action: HistoryAction,
    pub name: String,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: Option<OrganisationId>,
    pub metadata: Option<serde_json::Value>,
    pub source: HistorySource,
    pub target: Option<String>,
}
