use autometrics::autometrics;
use futures::FutureExt;
use futures::stream::{self, StreamExt};
use itertools::Either;
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaListQuery, CredentialSchemaRelations,
    GetCredentialSchemaList, UpdateCredentialSchemaRequest,
};
use one_core::model::organisation::Organisation;
use one_core::proto::transaction_manager::IsolationLevel;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Unchanged,
};
use shared_types::{CredentialSchemaId, OrganisationId};

use crate::common::calculate_pages_count;
use crate::credential_schema::CredentialSchemaProvider;
use crate::credential_schema::mapper::{claim_schemas_to_model_vec, credential_schema_from_models};
use crate::entity::credential_schema::LayoutType;
use crate::entity::{claim_schema, credential_schema, organisation};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::organisation::mapper::organisation_from_model;

#[autometrics]
#[async_trait::async_trait]
impl CredentialSchemaRepository for CredentialSchemaProvider {
    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError> {
        let claim_schemas = schema.claim_schemas.get().await?;

        let credential_schema: credential_schema::ActiveModel = schema.try_into()?;

        let credential_schema = self
            .db
            .tx_with_config(
                async {
                    let credential_schema = credential_schema
                        .insert(&self.db)
                        .await
                        .map_err(to_data_layer_error)?;

                    if !claim_schemas.is_empty() {
                        let claim_schema_models =
                            claim_schemas_to_model_vec(claim_schemas, &credential_schema.id);

                        claim_schema::Entity::insert_many(claim_schema_models)
                            .exec(&self.db)
                            .await
                            .map_err(|e| DataLayerError::Db(e.into()))?;
                    }

                    Ok::<_, DataLayerError>(credential_schema)
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;

        Ok(credential_schema.id)
    }

    async fn delete_credential_schema(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<(), DataLayerError> {
        let now = one_core::clock::now_utc();

        let credential_schema = credential_schema::ActiveModel {
            id: Unchanged(credential_schema.id),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        credential_schema::Entity::update(credential_schema)
            .filter(credential_schema::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        let credential_schema = credential_schema::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(credential_schema) = credential_schema else {
            return Ok(None);
        };

        let organisation = if let Some(_organisation_relations) = &relations.organisation {
            Some(
                self.organisation_repository
                    .get_organisation(&credential_schema.organisation_id)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "credential_schema-organisation",
                        id: credential_schema.organisation_id.to_string(),
                    })?,
            )
        } else {
            None
        };

        let credential_schema = credential_schema_from_models(
            credential_schema,
            organisation,
            false,
            self.db.to_owned(),
        )?;

        Ok(Some(credential_schema))
    }

    async fn get_credential_schema_list(
        &self,
        query_params: CredentialSchemaListQuery,
        relations: &CredentialSchemaRelations,
    ) -> Result<GetCredentialSchemaList, DataLayerError> {
        let limit = query_params
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

        let query = credential_schema::Entity::find()
            .filter(credential_schema::Column::DeletedAt.is_null())
            .with_list_query(&query_params)
            .order_by_desc(credential_schema::Column::CreatedDate)
            .order_by_desc(credential_schema::Column::Id);

        let (items_count, credential_schemas) =
            tokio::join!(query.to_owned().count(&self.db), query.all(&self.db));

        let items_count = items_count.map_err(|e| DataLayerError::Db(e.into()))?;
        let credential_schemas = credential_schemas.map_err(|e| DataLayerError::Db(e.into()))?;

        let organisations = if let Some(_organisations) = &relations.organisation {
            Either::Left(
                stream::iter(&credential_schemas)
                    .then(|credential_schema| async {
                        Ok::<_, DataLayerError>(Some(
                            self.organisation_repository
                                .get_organisation(&credential_schema.organisation_id)
                                .await?
                                .ok_or(DataLayerError::MissingRequiredRelation {
                                    relation: "credential_schema-organisation",
                                    id: credential_schema.organisation_id.to_string(),
                                })?,
                        ))
                    })
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?,
            )
        } else {
            Either::Right(std::iter::repeat(None::<Organisation>))
        };

        Ok(GetCredentialSchemaList {
            values: credential_schemas
                .into_iter()
                .zip(organisations.into_iter())
                .map(|(credential_schema, organisation)| {
                    credential_schema_from_models(
                        credential_schema,
                        organisation,
                        !query_params.include.as_ref().is_some_and(|include| {
                            include.contains(
                                &CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
                            )
                        }),
                        self.db.to_owned(),
                    )
                })
                .collect::<Result<_, _>>()?,
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }

    async fn update_credential_schema(
        &self,
        request: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError> {
        let id = &request.id;

        let revocation_method = match request.revocation_method {
            None => Unchanged(None),
            Some(revocation_method) => Set(revocation_method),
        };

        let format = match request.format {
            None => Unchanged("".into()), // Previously default empty string
            Some(format) => Set(format),
        };

        let layout_type = match request.layout_type {
            None => Unchanged(LayoutType::Card),
            Some(layout_type) => Set(layout_type.into()),
        };

        let layout_properties = match request.layout_properties {
            None => Unchanged(Default::default()),
            Some(layout_properties) => Set(Some(layout_properties.into())),
        };

        let update_model = credential_schema::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
            revocation_method,
            format,
            layout_type,
            layout_properties,
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        if let Some(claim_schemas) = request.claim_schemas {
            let claim_schema_models = claim_schemas_to_model_vec(claim_schemas, &request.id);

            claim_schema::Entity::insert_many(claim_schema_models)
                .exec(&self.db)
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;
        }

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn get_by_schema_id_and_organisation(
        &self,
        schema_id: &str,
        organisation_id: OrganisationId,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        let credential_schema = credential_schema::Entity::find()
            .filter(credential_schema::Column::SchemaId.eq(schema_id))
            .filter(credential_schema::Column::OrganisationId.eq(organisation_id))
            .filter(credential_schema::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(credential_schema) = credential_schema else {
            return Ok(None);
        };

        let mut organisation = None;
        if relations.organisation.is_some() {
            organisation = Some(organisation_from_model(
                credential_schema
                    .find_related(organisation::Entity)
                    .one(&self.db)
                    .await
                    .map_err(to_data_layer_error)?
                    .ok_or(DataLayerError::MappingError)?,
                &self.organisation_repository,
            ));
        }

        Ok(credential_schema_from_models(
            credential_schema,
            organisation,
            true,
            self.db.to_owned(),
        )?
        .into())
    }
}
