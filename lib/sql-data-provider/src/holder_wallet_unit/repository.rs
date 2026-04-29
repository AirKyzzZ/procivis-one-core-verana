use async_trait::async_trait;
use futures::FutureExt;
use one_core::model::holder_wallet_instance::{
    CreateHolderWalletInstanceRequest, GetHolderWalletInstanceList, HolderWalletInstance,
    HolderWalletInstanceListQuery, HolderWalletInstanceRelations,
    UpdateHolderWalletInstanceRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::holder_wallet_instance_repository::HolderWalletInstanceRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, Unchanged,
};
use shared_types::{HolderWalletInstanceId, OrganisationId};

use crate::common::list_query_with_custom_model;
use crate::entity::holder_wallet_instance;
use crate::holder_wallet_unit::HolderWalletInstanceProvider;
use crate::holder_wallet_unit::mapper::holder_wallet_instance_from_model;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[async_trait]
impl HolderWalletInstanceRepository for HolderWalletInstanceProvider {
    async fn create_holder_wallet_instance(
        &self,
        request: CreateHolderWalletInstanceRequest,
    ) -> Result<HolderWalletInstanceId, DataLayerError> {
        let model = holder_wallet_instance::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(model.id)
    }

    async fn get_holder_wallet_instance(
        &self,
        id: &HolderWalletInstanceId,
        relations: &HolderWalletInstanceRelations,
    ) -> Result<Option<HolderWalletInstance>, DataLayerError> {
        let model = holder_wallet_instance::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        let Some(model) = model else { return Ok(None) };

        let org_id = model.organisation_id;
        let auth_key_id = model.authentication_key_id;
        let mut holder_wallet_unit =
            holder_wallet_instance_from_model(model, &self.organisation_repository);
        if let (Some(_key_relations), Some(auth_key_id)) =
            (&relations.authentication_key, &auth_key_id)
        {
            let key = self.key_repository.get_key(auth_key_id).await?.ok_or(
                DataLayerError::MissingRequiredRelation {
                    relation: "holder_wallet_unit-authentication_key",
                    id: org_id.to_string(),
                },
            )?;
            holder_wallet_unit.authentication_key = Some(key)
        }

        if let Some(wallet_unit_attestation_relations) = &relations.wallet_unit_attestations {
            let attestations = self
                .wallet_unit_attestation_repository
                .get_wallet_instance_attestations_by_holder_wallet_unit(
                    id,
                    wallet_unit_attestation_relations,
                )
                .await?;
            holder_wallet_unit.wallet_unit_attestations = Some(attestations)
        }

        Ok(Some(holder_wallet_unit))
    }

    async fn get_holder_wallet_instance_by_org_id(
        &self,
        organisation_id: &OrganisationId,
    ) -> Result<Option<HolderWalletInstance>, DataLayerError> {
        let model = holder_wallet_instance::Entity::find()
            .filter(holder_wallet_instance::Column::OrganisationId.eq(organisation_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(model.map(|m| holder_wallet_instance_from_model(m, &self.organisation_repository)))
    }

    async fn update_holder_wallet_instance(
        &self,
        id: &HolderWalletInstanceId,
        request: UpdateHolderWalletInstanceRequest,
    ) -> Result<(), DataLayerError> {
        let action = async {
            let update_model = holder_wallet_instance::ActiveModel {
                id: Unchanged(*id),
                last_modified: Set(one_core::clock::now_utc()),
                status: request
                    .status
                    .map(|status| Set(status.into()))
                    .unwrap_or_default(),
                ..Default::default()
            };
            update_model
                .update(&self.db)
                .await
                .map_err(to_update_data_layer_error)?;

            let Some(attestations) = request.wallet_unit_attestations else {
                return Ok(());
            };

            for attestation in attestations {
                let result = self
                    .wallet_unit_attestation_repository
                    .create_wallet_instance_attestation(attestation.clone())
                    .await;
                if let Err(err) = result {
                    match err {
                        DataLayerError::AlreadyExists => {
                            let attestation_id = attestation.id;
                            self.wallet_unit_attestation_repository
                                .update_wallet_attestation(&attestation_id, attestation.into())
                                .await?
                        }
                        err => return Err(err),
                    }
                }
            }
            Ok(())
        }
        .boxed();
        self.db.tx(action).await?
    }

    async fn list_holder_wallet_instance(
        &self,
        query_params: HolderWalletInstanceListQuery,
    ) -> Result<GetHolderWalletInstanceList, DataLayerError> {
        let query = holder_wallet_instance::Entity::find()
            .with_list_query(&query_params)
            .order_by_desc(holder_wallet_instance::Column::CreatedDate)
            .order_by_desc(holder_wallet_instance::Column::Id);

        list_query_with_custom_model(query, query_params, &self.db, |m| {
            Ok(holder_wallet_instance_from_model(
                m,
                &self.organisation_repository,
            ))
        })
        .await
    }
}
