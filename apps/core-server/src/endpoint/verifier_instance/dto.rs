use one_core::service::verifier_instance::dto;
use one_dto_mapper::{From, Into};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, TrustCollectionId, VerifierInstanceId};
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::RegisterVerifierInstanceRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterVerifierInstanceRequestRestDTO {
    /// The verifier unit's organization.
    pub organisation_id: OrganisationId,
    /// The Verifier Provider's reference URL.
    pub verifier_provider_url: String,
    /// Reference a configured `verifierProvider` instance.
    pub r#type: String,
    #[serde(default)]
    pub trusted_issuer_required: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::RegisterVerifierInstanceResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct RegisterVerifierInstanceResponseRestDTO {
    pub id: VerifierInstanceId,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::EditVerifierInstanceRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EditVerifierInstanceRequestRestDTO {
    pub trust_collections: Option<Vec<TrustCollectionId>>,
    pub trusted_issuer_required: Option<bool>,
}
