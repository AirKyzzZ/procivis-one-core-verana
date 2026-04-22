use proc_macros::Model;
use shared_types::TrustAnchorId;
use time::OffsetDateTime;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct TrustAnchor {
    #[model(id)]
    pub id: TrustAnchorId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub r#type: String,
    pub publisher_reference: String,
    pub is_publisher: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactTrustAnchorFilterColumn {
    Name,
    Type,
}
