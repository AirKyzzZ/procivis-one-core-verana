use std::collections::HashMap;

use one_core::provider::signer::registration_certificate::model::SupervisoryAuthority;
use one_core::service::common_dto::{
    EudiIntermediaryResponseDTO, EudiTrustInformationResponseDTO, TrustInformationDetailResponseDTO,
};
use one_dto_mapper::{From, convert_inner};
use proc_macros::options_not_nullable;
use serde::Serialize;
use url::Url;
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(TrustInformationDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustInformationDetailResponseRestDTO {
    /// EUDI trust information received from Access Certificates,
    /// Registration Certificates, or National Registry public APIs.
    #[from(with_fn = convert_inner)]
    pub eudi_ecosystem: Option<EudiTrustInformationResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(EudiTrustInformationResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EudiTrustInformationResponseRestDTO {
    pub name: String,
    pub website: Url,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
    pub identifier: String,
    #[schema(example = json!([{ "de": "Demo Dienstleistung", "en": "Demo Service" }]))]
    pub service_description: Vec<HashMap<String, String>>,
    pub supervisory_authority: EudiSupervisoryAuthorityResponseRestDTO,
    #[from(with_fn = convert_inner)]
    pub intermediary: Option<EudiIntermediaryResponseRestDTO>,
    pub is_public_sector: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SupervisoryAuthority)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EudiSupervisoryAuthorityResponseRestDTO {
    pub email: String,
    pub phone: String,
    pub uri: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(EudiIntermediaryResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EudiIntermediaryResponseRestDTO {
    pub name: Option<String>,
    pub identifier: String,
    pub website: Url,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
}

#[derive(Debug, Clone, Serialize, From, ToSchema)]
#[from("one_core::model::history::TrustResolutionResult")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustResolutionResultRestEnum {
    Trusted,
    Untrusted,
    Unknown,
}
