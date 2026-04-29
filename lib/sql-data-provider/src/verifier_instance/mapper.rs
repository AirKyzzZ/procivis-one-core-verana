use std::sync::Arc;

use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::model::verifier_instance::{
    SortableVerifierInstanceColumn, VerifierInstance, VerifierInstanceFilterValue,
};
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::{Condition, Set};

use crate::entity::verifier_instance::{ActiveModel, Model};
use crate::list_query_generic::{IntoFilterCondition, IntoSortingColumn};

pub(crate) fn verifier_instance_from_model(
    model: Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> VerifierInstance {
    VerifierInstance {
        id: model.id,
        created_date: model.created_date,
        last_modified: model.last_modified,
        provider_type: model.provider_type,
        provider_name: model.provider_name,
        provider_url: model.provider_url,
        trusted_issuer_required: model.trusted_issuer_required,
        organisation: Related::new(model.organisation_id, organisation_repository.to_owned()),
    }
}

impl From<VerifierInstance> for ActiveModel {
    fn from(value: VerifierInstance) -> Self {
        let now = one_core::clock::now_utc();
        Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            provider_name: Set(value.provider_name),
            provider_type: Set(value.provider_type),
            provider_url: Set(value.provider_url),
            trusted_issuer_required: Set(value.trusted_issuer_required),
            organisation_id: Set(value.organisation.id()),
        }
    }
}

impl IntoSortingColumn for SortableVerifierInstanceColumn {
    fn get_column(&self) -> SimpleExpr {
        match *self {}
    }
}
impl IntoFilterCondition for VerifierInstanceFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {}
    }
}
