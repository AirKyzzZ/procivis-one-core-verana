use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, DidId, IdentifierId, InteractionId, KeyId, OrganisationId, ProofId,
    ProofSchemaId,
};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::model::proof::{ExactProofFilterColumn, ProofRole, ProofStateEnum, SortableProofColumn};
use crate::proto::trust_information::dto::TrustInformation;
use crate::provider::verification_protocol::openid4vp::model::ClientIdScheme;
use crate::service::certificate::dto::CertificateResponseDTO;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
};
use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;
use crate::service::proof_schema::dto::{GetProofSchemaListItemDTO, ProofClaimSchemaResponseDTO};

#[derive(Clone, Debug)]
pub struct CreateProofRequestDTO {
    pub proof_schema_id: ProofSchemaId,
    pub verifier_did_id: Option<DidId>,
    pub verifier_identifier_id: Option<IdentifierId>,
    pub protocol: String,
    pub redirect_uri: Option<String>,
    pub verifier_key: Option<KeyId>,
    pub verifier_certificate: Option<CertificateId>,
    pub iso_mdl_engagement: Option<String>,
    pub transport: Option<Vec<String>>,
    pub profile: Option<String>,
    pub engagement: Option<String>,
    pub webhook_destination_url: Option<String>,
    pub subscriber_information: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CreateProofResponseDTO {
    pub id: ProofId,
}

#[derive(Clone, Debug)]
pub struct ProofDetailResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub retain_until_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub verifier: Option<GetIdentifierListItemResponseDTO>,
    pub verifier_certificate: Option<CertificateResponseDTO>,
    pub protocol: String,
    pub transport: String,
    pub engagement: Option<String>,
    pub state: ProofStateEnum,
    pub role: ProofRole,
    pub organisation_id: OrganisationId,
    pub schema: Option<GetProofSchemaListItemDTO>,
    pub redirect_uri: Option<String>,
    pub proof_inputs: Vec<ProofInputDTO>,
    pub claims_removed_at: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub webhook_destination_url: Option<String>,
    pub trust_information: Option<TrustInformation>,
    pub subscriber_information: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ProofListItemResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub retain_until_date: Option<OffsetDateTime>,
    pub verifier: Option<GetIdentifierListItemResponseDTO>,
    pub protocol: String,
    pub engagement: Option<String>,
    pub transport: String,
    pub state: ProofStateEnum,
    pub role: ProofRole,
    pub schema: Option<GetProofSchemaListItemDTO>,
    pub profile: Option<String>,
    pub webhook_destination_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ProofClaimDTO {
    pub schema: ProofClaimSchemaResponseDTO,
    pub path: String,
    pub value: Option<ProofClaimValueDTO>,
}

#[derive(Clone, Debug)]
pub enum ProofClaimValueDTO {
    Value(String),
    Claims(Vec<ProofClaimDTO>),
}

#[derive(Clone, Debug)]
pub struct ProofInputDTO {
    pub claims: Vec<ProofClaimDTO>,
    pub credential: Option<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>>,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
}

pub type GetProofListResponseDTO = GetListResponse<ProofListItemResponseDTO>;

#[derive(Debug, Clone)]
pub enum ProofFilterValue {
    Name(StringMatch),
    OrganisationId(OrganisationId),
    States(Vec<ProofStateEnum>),
    Roles(Vec<ProofRole>),
    ProofIds(Vec<ProofId>),
    ProofIdsNot(Vec<ProofId>),
    ProofSchemaIds(Vec<ProofSchemaId>),
    VerifierIds(Vec<IdentifierId>),
    Profiles(Vec<String>),
    ValidForDeletion,
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    RequestedDate(ValueComparison<OffsetDateTime>),
    CompletedDate(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for ProofFilterValue {}

pub type GetProofQueryDTO = ListQuery<SortableProofColumn, ProofFilterValue>;

#[derive(Clone, Debug)]
pub struct ProofFilterParamsDTO {
    pub name: Option<String>,
    pub exact: Option<Vec<ExactProofFilterColumn>>,
    pub states: Option<Vec<ProofStateEnum>>,
    pub roles: Option<Vec<ProofRole>>,
    pub ids: Option<Vec<ProofId>>,
    pub proof_schema_ids: Option<Vec<ProofSchemaId>>,
    pub verifier_ids: Option<Vec<IdentifierId>>,
    pub profiles: Option<Vec<String>>,
    pub organisation_id: OrganisationId,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub requested_date_after: Option<OffsetDateTime>,
    pub requested_date_before: Option<OffsetDateTime>,
    pub completed_date_after: Option<OffsetDateTime>,
    pub completed_date_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct ProposeProofResponseDTO {
    pub proof_id: ProofId,
    pub interaction_id: InteractionId,
    pub url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateProofInteractionData {
    pub transport: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ShareProofRequestDTO {
    pub params: Option<ShareProofRequestParamsDTO>,
}

#[derive(Clone, Debug, Default)]
pub struct ShareProofRequestParamsDTO {
    pub client_id_scheme: Option<ClientIdScheme>,
}

#[derive(Clone, Debug)]
pub struct ProposeProofRequestDTO {
    pub protocol: String,
    pub organisation_id: OrganisationId,
    pub engagement: Vec<String>,
    pub ui_message: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ShareProofResponseDTO {
    pub url: String,
    pub expires_at: Option<OffsetDateTime>,
}
