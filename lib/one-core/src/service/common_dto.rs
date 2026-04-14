use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::model::common::SortDirection;
use crate::model::list_query::NoInclude;
use crate::provider::signer::registration_certificate::model::SupervisoryAuthority;

pub const KB: usize = 1 << 10;
pub const MB: usize = KB << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundedB64Image<const MAX: usize>(pub(crate) String);

#[derive(Clone, Debug)]
pub struct ListQueryDTO<SortColumn, Filter, Include = NoInclude> {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortColumn>,
    pub sort_direction: Option<SortDirection>,

    pub filter: Filter,
    pub include: Option<Vec<Include>>,
}

#[derive(Clone, Debug)]
pub struct TrustInformationDetailResponseDTO {
    pub eudi_ecosystem: Option<EudiTrustInformationResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct EudiTrustInformationResponseDTO {
    pub name: String,
    pub website: Url,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
    pub identifier: String,
    pub service_description: Vec<HashMap<String, String>>,
    pub supervisory_authority: SupervisoryAuthority,
    pub intermediary: Option<EudiIntermediaryResponseDTO>,
    pub is_public_sector: bool,
}

#[derive(Clone, Debug)]
pub struct EudiIntermediaryResponseDTO {
    pub name: Option<String>,
    pub identifier: String,
    pub website: Url,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
}
