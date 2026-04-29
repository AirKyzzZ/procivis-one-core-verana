use std::sync::Arc;

use entity::{holder_wallet_instance, wallet_instance};
use one_core::model::holder_wallet_instance::{
    CreateHolderWalletInstanceRequest, HolderWalletInstance, HolderWalletInstanceFilterValue,
    SortableHolderWalletInstanceColumn,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::model::wallet_instance::{WalletInstanceStatus, WalletProviderType};
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::{Condition, Set};

use crate::entity;
use crate::entity::holder_wallet_instance::{ActiveModel, Model};
use crate::list_query_generic::{IntoFilterCondition, IntoSortingColumn, get_equals_condition};

pub(crate) fn holder_wallet_instance_from_model(
    value: Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> HolderWalletInstance {
    HolderWalletInstance {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        wallet_provider_type: WalletProviderType::from(value.wallet_provider_type),
        wallet_provider_name: value.wallet_provider_name,
        wallet_provider_url: value.wallet_provider_url,
        provider_wallet_unit_id: value.provider_wallet_unit_id,
        status: WalletInstanceStatus::from(value.status),
        organisation: Related::new(value.organisation_id, organisation_repository.clone()),
        authentication_key: None,
        wallet_unit_attestations: None,
    }
}

impl From<CreateHolderWalletInstanceRequest> for ActiveModel {
    fn from(value: CreateHolderWalletInstanceRequest) -> Self {
        let now = one_core::clock::now_utc();
        Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            status: Set(value.status.into()),
            wallet_provider_name: Set(value.wallet_provider_name),
            wallet_provider_type: Set(value.wallet_provider_type.into()),
            wallet_provider_url: Set(value.wallet_provider_url),
            provider_wallet_unit_id: Set(value.provider_wallet_unit_id),
            organisation_id: Set(value.organisation.id),
            authentication_key_id: Set(value.authentication_key.map(|key| key.id)),
        }
    }
}

impl IntoSortingColumn for SortableHolderWalletInstanceColumn {
    fn get_column(&self) -> SimpleExpr {
        match *self {}
    }
}

impl IntoFilterCondition for HolderWalletInstanceFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            HolderWalletInstanceFilterValue::Status(status) => get_equals_condition(
                holder_wallet_instance::Column::Status,
                wallet_instance::WalletInstanceStatus::from(status),
            ),
        }
    }
}
