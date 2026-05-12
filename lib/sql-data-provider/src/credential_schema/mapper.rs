use std::sync::Arc;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::{
    CredentialSchema, SortableCredentialSchemaColumn, TransactionCode,
};
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::{AsyncVecLoader, Related, RelatedVec};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::sea_query::{ExprTrait, Query, SimpleExpr};
use sea_orm::{ColumnTrait, Condition, EntityTrait, IntoSimpleExpr, QueryFilter, QueryOrder};
use shared_types::CredentialSchemaId;
use uuid::Uuid;

use crate::TransactionManagerImpl;
use crate::claim_schema::mapper::claim_schema_from_model;
use crate::credential_schema_format::mapper::credential_schema_format_from_model;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::{claim_schema, credential_schema, credential_schema_format};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};
use crate::localized_text::LocalizedTextLoader;
use crate::mapper::to_data_layer_error;

impl IntoSortingColumn for SortableCredentialSchemaColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => credential_schema::Column::CreatedDate.into_simple_expr(),
            Self::Name => credential_schema::Column::Name.into_simple_expr(),
            Self::Format => credential_schema::Column::Format.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for CredentialSchemaFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(credential_schema::Column::Name, string_match)
            }
            Self::SchemaId(string_match) => Condition::any()
                .add(
                    credential_schema::Column::Id.in_subquery(
                        Query::select()
                            .column(credential_schema_format::Column::CredentialSchemaId)
                            .from(credential_schema_format::Entity)
                            .cond_where(
                                get_string_match_condition(
                                    credential_schema_format::Column::SchemaId,
                                    string_match.clone(),
                                )
                                .into_condition(),
                            )
                            .to_owned(),
                    ),
                )
                .add(get_string_match_condition(
                    credential_schema::Column::SchemaId,
                    string_match,
                )),
            Self::SchemaIds(schema_ids) => Condition::any()
                .add(
                    credential_schema::Column::Id.in_subquery(
                        Query::select()
                            .column(credential_schema_format::Column::CredentialSchemaId)
                            .from(credential_schema_format::Entity)
                            .cond_where(
                                credential_schema_format::Column::SchemaId
                                    .is_in(schema_ids.clone()),
                            )
                            .to_owned(),
                    ),
                )
                .add(credential_schema::Column::SchemaId.is_in(schema_ids)),
            Self::Formats(formats) => Condition::any()
                .add(
                    credential_schema::Column::Id.in_subquery(
                        Query::select()
                            .column(credential_schema_format::Column::CredentialSchemaId)
                            .from(credential_schema_format::Entity)
                            .cond_where(
                                credential_schema_format::Column::Format.is_in(formats.clone()),
                            )
                            .to_owned(),
                    ),
                )
                .add(credential_schema::Column::Format.is_in(formats)),
            Self::OrganisationId(organisation_id) => get_equals_condition(
                credential_schema::Column::OrganisationId,
                organisation_id.to_string(),
            ),
            Self::CredentialSchemaIds(ids) => credential_schema::Column::Id
                .is_in(ids.iter())
                .into_condition(),
            Self::CreatedDate(value) => {
                get_comparison_condition(credential_schema::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(credential_schema::Column::LastModified, value)
            }
            Self::RequiresWalletInstanceAttestation(requires_wia) => get_equals_condition(
                credential_schema::Column::RequiresWalletInstanceAttestation,
                requires_wia,
            ),
            Self::KeyStorageSecurity(security_levels) => {
                let security_levels: Vec<KeyStorageSecurity> = convert_inner(security_levels);
                credential_schema::Column::KeyStorageSecurity
                    .is_in(security_levels)
                    .into_condition()
            }
            Self::UsesBatchIssuance(uses_batch_issuance) => {
                if uses_batch_issuance {
                    credential_schema::Column::BatchSize
                        .is_not_null()
                        .into_condition()
                } else {
                    credential_schema::Column::BatchSize
                        .is_null()
                        .into_condition()
                }
            }
            Self::IsMultiformatSchema(is_multiformat) => {
                let subquery = Query::select()
                    .column(credential_schema_format::Column::CredentialSchemaId)
                    .from(credential_schema_format::Entity)
                    .group_by_col(credential_schema_format::Column::CredentialSchemaId)
                    .and_having(
                        sea_orm::sea_query::Expr::col(
                            credential_schema_format::Column::CredentialSchemaId,
                        )
                        .count()
                        .gt(1_i32),
                    )
                    .to_owned();

                if is_multiformat {
                    credential_schema::Column::Id
                        .in_subquery(subquery)
                        .into_condition()
                } else {
                    credential_schema::Column::Id
                        .not_in_subquery(subquery)
                        .into_condition()
                }
            }
        }
    }
}

impl From<CredentialSchema> for credential_schema::ActiveModel {
    fn from(value: CredentialSchema) -> Self {
        let (transaction_code_type, transaction_code_length, transaction_code_description) =
            match value.transaction_code {
                Some(code) => (
                    Some(code.r#type.into()),
                    Some(code.length),
                    code.description,
                ),
                None => (None, None, None),
            };

        Self {
            id: Set(value.id),
            deleted_at: Set(value.deleted_at),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            imported_source_url: Set(value.imported_source_url),
            format: Set(None),
            revocation_method: Set(value.revocation_method),
            organisation_id: Set(value.organisation.id()),
            key_storage_security: Set(convert_inner(value.key_storage_security)),
            layout_type: Set(value.layout_type.into()),
            layout_properties: Set(convert_inner(value.layout_properties)),
            schema_id: Set(None),
            allow_suspension: Set(value.allow_suspension),
            requires_wallet_instance_attestation: Set(value.requires_wallet_instance_attestation),
            transaction_code_type: Set(transaction_code_type),
            transaction_code_length: Set(transaction_code_length.map(|l| l as i32)),
            transaction_code_description: Set(transaction_code_description),
            batch_size: Set(value.batch_size),
            allow_revocation: Set(value.allow_revocation),
        }
    }
}

pub(super) fn claim_schemas_to_model_vec(
    claim_schemas: Vec<ClaimSchema>,
    credential_schema_id: &CredentialSchemaId,
) -> Vec<claim_schema::ActiveModel> {
    claim_schemas
        .into_iter()
        .enumerate()
        .map(|(index, claim_schema)| claim_schema::ActiveModel {
            id: Set(claim_schema.id),
            created_date: Set(claim_schema.created_date),
            last_modified: Set(claim_schema.last_modified),
            key: Set(claim_schema.key),
            business_key: Set(claim_schema.business_key),
            datatype: Set(claim_schema.data_type),
            array: Set(claim_schema.array),
            metadata: Set(claim_schema.metadata),
            credential_schema_id: Set(*credential_schema_id),
            required: Set(claim_schema.required),
            order: Set(index as i32),
        })
        .collect()
}

pub(super) fn credential_schema_from_models(
    credential_schema: credential_schema::Model,
    skip_layout_properties: bool,
    db: TransactionManagerImpl,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Result<CredentialSchema, DataLayerError> {
    let transaction_code = match (
        credential_schema.transaction_code_type,
        credential_schema.transaction_code_length,
    ) {
        (Some(r#type), Some(length)) => Some(TransactionCode {
            r#type: r#type.into(),
            length: length as u32,
            description: credential_schema.transaction_code_description,
        }),
        (None, None) => None,
        _ => return Err(DataLayerError::MappingError),
    };

    let id = credential_schema.id;
    let formats = match (credential_schema.format, credential_schema.schema_id) {
        (Some(format), Some(schema_id)) => RelatedVec::from(vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: credential_schema.created_date,
            last_modified: credential_schema.last_modified,
            credential_schema_id: credential_schema.id,
            format,
            schema_id,
            claim_mappings: RelatedVec::default(),
        }]),
        _ => RelatedVec::new(CredentialSchemaFormatsLoader { id, db: db.clone() }),
    };
    Ok(CredentialSchema {
        id,
        deleted_at: credential_schema.deleted_at,
        created_date: credential_schema.created_date,
        last_modified: credential_schema.last_modified,
        name: credential_schema.name,
        key_storage_security: convert_inner(credential_schema.key_storage_security),
        formats,
        revocation_method: credential_schema.revocation_method,
        claim_schemas: RelatedVec::new(ClaimSchemasLoader { id, db: db.clone() }),
        organisation: Related::new(
            credential_schema.organisation_id,
            organisation_repository.to_owned(),
        ),
        layout_type: credential_schema.layout_type.into(),
        layout_properties: if skip_layout_properties {
            None
        } else {
            convert_inner(credential_schema.layout_properties)
        },
        imported_source_url: credential_schema.imported_source_url,
        allow_suspension: credential_schema.allow_suspension,
        requires_wallet_instance_attestation: credential_schema
            .requires_wallet_instance_attestation,
        transaction_code,
        batch_size: credential_schema.batch_size,
        allow_revocation: credential_schema.allow_revocation,
        translations: RelatedVec::new(LocalizedTextLoader { id: id.into(), db }),
    })
}

pub(crate) struct ClaimSchemasLoader {
    pub id: CredentialSchemaId,
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncVecLoader<ClaimSchema> for ClaimSchemasLoader {
    async fn load(&self) -> Result<Vec<ClaimSchema>, DataLayerError> {
        let claim_schemas = claim_schema::Entity::find()
            .filter(claim_schema::Column::CredentialSchemaId.eq(self.id.to_string()))
            .order_by_asc(claim_schema::Column::Order)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(claim_schemas
            .into_iter()
            .map(|m| claim_schema_from_model(m, self.db.clone()))
            .collect())
    }
}

pub(crate) struct CredentialSchemaFormatsLoader {
    pub id: CredentialSchemaId,
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncVecLoader<CredentialSchemaFormat> for CredentialSchemaFormatsLoader {
    async fn load(&self) -> Result<Vec<CredentialSchemaFormat>, DataLayerError> {
        let credential_schema_formats = credential_schema_format::Entity::find()
            .filter(credential_schema_format::Column::CredentialSchemaId.eq(self.id.to_string()))
            .order_by_asc(credential_schema_format::Column::CreatedDate)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(credential_schema_formats
            .into_iter()
            .map(|m| credential_schema_format_from_model(m, self.db.clone()))
            .collect())
    }
}
