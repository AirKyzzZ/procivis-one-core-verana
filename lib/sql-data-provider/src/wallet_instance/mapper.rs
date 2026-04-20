use one_core::model::history::HistoryMetadata;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::wallet_instance::{
    SortableWalletInstanceColumn, WalletInstance, WalletInstanceFilterValue, WalletInstanceOs,
    WalletInstanceStatus, WalletProviderType,
};
use one_core::repository::error::DataLayerError;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::sea_query::{Query, SimpleExpr};
use sea_orm::{ColumnTrait, Condition, IntoSimpleExpr};

use crate::entity::{history, wallet_instance};
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_comparison_condition, get_equals_condition, get_string_match_condition,
};

impl TryFrom<wallet_instance::Model> for WalletInstance {
    type Error = DataLayerError;

    fn try_from(value: wallet_instance::Model) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            os: WalletInstanceOs::from(value.os),
            status: WalletInstanceStatus::from(value.status),
            wallet_provider_type: WalletProviderType::from(value.wallet_provider_type),
            wallet_provider_name: value.wallet_provider_name,
            authentication_key_jwk: value
                .authentication_key_jwk
                .map(|jwk| serde_json::from_str(&jwk))
                .transpose()
                .map_err(|_| DataLayerError::MappingError)?,
            last_issuance: value.last_issuance,
            name: value.name,
            organisation: None,
            nonce: value.nonce,
            attested_keys: None,
        })
    }
}

impl IntoSortingColumn for SortableWalletInstanceColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => wallet_instance::Column::CreatedDate.into_simple_expr(),
            Self::LastModified => wallet_instance::Column::LastModified.into_simple_expr(),
            Self::Name => wallet_instance::Column::Name.into_simple_expr(),
            Self::Status => wallet_instance::Column::Status.into_simple_expr(),
            Self::Os => wallet_instance::Column::Os.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for WalletInstanceFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(wallet_instance::Column::OrganisationId, organisation_id)
            }
            Self::Name(string_match) => {
                get_string_match_condition(wallet_instance::Column::Name, string_match)
            }
            Self::Ids(ids) => wallet_instance::Column::Id
                .is_in(ids.iter())
                .into_condition(),
            Self::Status(statuses) => wallet_instance::Column::Status
                .is_in(
                    statuses
                        .into_iter()
                        .map(wallet_instance::WalletInstanceStatus::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::WalletProviderType(types) => wallet_instance::Column::WalletProviderType
                .is_in(types.iter())
                .into_condition(),
            Self::Os(os_values) => wallet_instance::Column::Os
                .is_in(
                    os_values
                        .into_iter()
                        .map(wallet_instance::WalletInstanceOs::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::AttestationHash(attestation_hash) => {
                let history_metadata = HistoryMetadata::WalletUnitJWT(attestation_hash);
                #[allow(clippy::expect_used)]
                let history_metadata_json = serde_json::to_string(&history_metadata)
                    .expect("Failed to serialize history metadata");
                wallet_instance::Column::Id
                    .in_subquery(
                        Query::select()
                            .column(history::Column::EntityId)
                            .from(history::Entity)
                            .cond_where(
                                Condition::all()
                                    .add(
                                        history::Column::EntityType
                                            .eq(history::HistoryEntityType::WalletUnit),
                                    )
                                    .add(
                                        history::Column::Action
                                            .is_in([history::HistoryAction::Issued]),
                                    )
                                    .add(history::Column::Metadata.eq(history_metadata_json)),
                            )
                            .to_owned(),
                    )
                    .into_condition()
            }
            Self::CreatedDate(comparison) => {
                get_comparison_condition(wallet_instance::Column::CreatedDate, comparison)
            }
            Self::LastModified(comparison) => {
                get_comparison_condition(wallet_instance::Column::LastModified, comparison)
            }
        }
    }
}

impl IntoJoinRelations for WalletInstanceFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        // No joins needed for wallet unit filters
        vec![]
    }
}
