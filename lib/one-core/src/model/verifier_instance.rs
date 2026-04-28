use shared_types::VerifierInstanceId;
use time::OffsetDateTime;

use crate::model::organisation::Organisation;
use crate::model::relation::Related;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct VerifierInstance {
    pub id: VerifierInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub provider_type: String,
    pub provider_name: String,
    pub provider_url: String,
    pub trusted_issuer_required: bool,

    pub organisation: Related<Organisation>,
}
