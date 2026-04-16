use std::str::FromStr;

use itertools::Itertools;
use one_core::model::certificate::{
    Certificate, CertificateFilterValue, CertificateRole, SortableCertificateColumn,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::repository::error::DataLayerError;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr, Set};

use crate::entity::certificate::{self, ActiveModel};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};

impl From<Certificate> for ActiveModel {
    fn from(certificate: Certificate) -> Self {
        let key_id = certificate.key.map(|key| key.id);

        let roles = if !certificate.roles.is_empty() {
            Some(certificate.roles.iter().join(","))
        } else {
            None
        };
        Self {
            id: Set(certificate.id),
            identifier_id: Set(certificate.identifier_id),
            created_date: Set(certificate.created_date),
            last_modified: Set(certificate.last_modified),
            expiry_date: Set(certificate.expiry_date),
            name: Set(certificate.name),
            chain: Set(certificate.chain),
            fingerprint: Set(certificate.fingerprint),
            state: Set(certificate.state.into()),
            key_id: Set(key_id),
            organisation_id: Set(certificate.organisation_id),
            roles: Set(roles),
            deleted_at: Set(certificate.deleted_at),
        }
    }
}

impl TryFrom<certificate::Model> for Certificate {
    type Error = DataLayerError;
    fn try_from(value: certificate::Model) -> Result<Self, Self::Error> {
        let roles = if let Some(value) = value.roles {
            value
                .split(",")
                .map(CertificateRole::from_str)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| DataLayerError::MappingError)?
        } else {
            vec![]
        };
        Ok(Self {
            id: value.id,
            identifier_id: value.identifier_id,
            organisation_id: value.organisation_id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiry_date: value.expiry_date,
            name: value.name,
            chain: value.chain,
            fingerprint: value.fingerprint,
            state: value.state.into(),
            roles,
            key: None,
            deleted_at: value.deleted_at,
        })
    }
}

impl IntoSortingColumn for SortableCertificateColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => certificate::Column::Name,
            Self::CreatedDate => certificate::Column::CreatedDate,
            Self::State => certificate::Column::State,
            Self::ExpiryDate => certificate::Column::ExpiryDate,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for CertificateFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Ids(ids) => certificate::Column::Id.is_in(ids).into_condition(),
            Self::Name(string_match) => {
                get_string_match_condition(certificate::Column::Name, string_match)
            }
            Self::State(state) => get_equals_condition(
                certificate::Column::State,
                certificate::CertificateState::from(state),
            ),
            Self::ExpiryDate(date_comparison) => {
                get_comparison_condition(certificate::Column::ExpiryDate, date_comparison)
            }
            Self::Fingerprint(fingerprint) => {
                get_equals_condition(certificate::Column::Fingerprint, fingerprint)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(certificate::Column::OrganisationId, organisation_id)
            }
        }
    }
}
