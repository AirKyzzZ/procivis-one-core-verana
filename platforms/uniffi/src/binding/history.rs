use one_core::model::history::{
    HistoryAction, HistoryEntityType, HistorySearchEnum, SortableHistoryColumn,
};
use one_core::service::history::dto::{GetHistoryListResponseDTO, WalletRelayingPartyMetadataDTO};
use one_dto_mapper::{From, Into, convert_inner};

use super::backup::UnexportableEntitiesBindingDTO;
use super::common::SortDirection;
use crate::OneCore;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Returns details on a single event.
    #[uniffi::method]
    pub async fn get_history_entry(
        &self,
        history_id: String,
    ) -> Result<HistoryListItemBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .history_service
            .get_history_entry(into_id(&history_id)?)
            .await?
            .into())
    }

    /// Returns a filterable list of history events.
    #[uniffi::method]
    pub async fn list_history(
        &self,
        query: HistoryListQueryBindingDTO,
    ) -> Result<HistoryListBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .history_service
            .get_history_list(query.try_into()?)
            .await?
            .into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(HistoryAction)]
#[into(HistoryAction)]
#[uniffi(name = "HistoryAction")]
pub enum HistoryActionBindingEnum {
    Accepted,
    Created,
    CsrGenerated,
    Deactivated,
    Deleted,
    Errored,
    Issued,
    Offered,
    Rejected,
    Requested,
    Revoked,
    Suspended,
    Pending,
    Restored,
    Shared,
    Imported,
    ClaimsRemoved,
    Activated,
    Withdrawn,
    Removed,
    Retracted,
    Updated,
    Reactivated,
    Expired,
    InteractionCreated,
    InteractionErrored,
    InteractionExpired,
    Delivered,
    WrpAcReceived,
    WrpRcReceived,
    WrpNrReceived,
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(HistoryEntityType)]
#[into(HistoryEntityType)]
#[uniffi(name = "HistoryEntityType")]
pub enum HistoryEntityTypeBindingEnum {
    Key,
    Did,
    Identifier,
    Certificate,
    Credential,
    CredentialSchema,
    Proof,
    ProofSchema,
    Organisation,
    Backup,
    TrustAnchor,
    TrustEntity,
    WalletUnit,
    User,
    Provider,
    WalletRelyingParty,
    StsRole,
    StsOrganisation,
    StsIamRole,
    StsSession,
    StsToken,
    Signature,
    Notification,
    SupervisoryAuthority,
    TrustListPublication,
    TrustCollection,
    TrustListSubscription,
    VerifierInstance,
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "HistoryMetadata")]
pub enum HistoryMetadataBinding {
    UnexportableEntities {
        value: UnexportableEntitiesBindingDTO,
    },
    ErrorMetadata {
        value: HistoryErrorMetadataBindingDTO,
    },
    WalletUnitJWT(String),
    WalletRelayingParty {
        value: WalletRelayingPartyMetadataBindingDTO,
    },
}

#[derive(Debug, Clone, uniffi::Record)]
#[uniffi(name = "MultiLangString")]
pub struct MultiLangStringBindingDTO {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, uniffi::Record)]
#[uniffi(name = "HistoryErrorMetadata")]
pub struct HistoryErrorMetadataBindingDTO {
    pub error_code: String,
    pub message: String,
}

#[derive(Debug, Clone, From, uniffi::Record)]
#[from(WalletRelayingPartyMetadataDTO)]
#[uniffi(name = "WalletRelayingPartyMetadata")]
pub struct WalletRelayingPartyMetadataBindingDTO {
    pub name: String,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HistoryListItem")]
pub struct HistoryListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub action: HistoryActionBindingEnum,
    pub name: String,
    pub entity_id: Option<String>,
    pub entity_type: HistoryEntityTypeBindingEnum,
    pub metadata: Option<HistoryMetadataBinding>,
    pub organisation_id: Option<String>,
    pub target: Option<String>,
    pub user: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableHistoryColumn)]
#[uniffi(name = "SortableHistoryColumn")]
pub enum SortableHistoryColumnBindingEnum {
    CreatedDate,
    Action,
    EntityType,
    Source,
    User,
    OrganisationId,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HistoryListQuery")]
pub struct HistoryListQueryBindingDTO {
    /// Page number to retrieve (0-based indexing).
    pub page: u32,
    /// Number of items to return per page.
    pub page_size: u32,
    /// Field value to sort results by.
    pub sort: Option<SortableHistoryColumnBindingEnum>,
    /// Direction to sort results by.
    pub sort_direction: Option<SortDirection>,
    /// Specifies the organizational context for this operation.
    pub organisation_id: String,
    /// Return only events associated with the provided entity IDs.
    pub entity_ids: Option<Vec<String>>,
    /// Return only events associated with the provided entity types.
    pub entity_types: Option<Vec<HistoryEntityTypeBindingEnum>>,
    /// Return only the provided events.
    pub actions: Option<Vec<HistoryActionBindingEnum>>,
    /// Return only entries created after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_after: Option<String>,
    /// Return only entries created before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_before: Option<String>,
    /// Return only events associated with the provided identifier ID.
    pub identifier_id: Option<String>,
    /// Return only events associated with the provided credential ID.
    pub credential_id: Option<String>,
    /// Return only events associated with the provided credential schema ID.
    pub credential_schema_id: Option<String>,
    /// Return only events associated with the provided proof ID.
    pub proof_id: Option<String>,
    /// Return only events associated with the provided proof schema ID.
    pub proof_schema_id: Option<String>,
    /// Search for a string.
    pub search: Option<HistorySearchBindingDTO>,
    /// Return only events associated with the provided user(s).
    pub users: Option<Vec<String>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetHistoryListResponseDTO)]
#[uniffi(name = "HistoryList")]
pub struct HistoryListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<HistoryListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(HistorySearchEnum)]
#[uniffi(name = "HistorySearchType")]
pub enum HistorySearchTypeBindingEnum {
    All,
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
    IssuerDid,
    IssuerName,
    VerifierDid,
    VerifierName,
    ProofSchemaName,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HistorySearch")]
pub struct HistorySearchBindingDTO {
    pub text: String,
    pub r#type: Option<HistorySearchTypeBindingEnum>,
}
