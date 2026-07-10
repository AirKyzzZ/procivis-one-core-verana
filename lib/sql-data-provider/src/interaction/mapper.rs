use std::sync::Arc;

use one_core::model::interaction::{Interaction, UpdateInteractionRequest};
use one_core::model::relation::Related;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::Set;

use crate::entity::interaction;

impl From<Interaction> for interaction::ActiveModel {
    fn from(value: Interaction) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            data: Set(value.data),
            organisation_id: Set(value.organisation.id()),
            nonce_id: Set(value.nonce_id),
            interaction_type: Set(value.interaction_type.into()),
            expires_at: Set(value.expires_at),
        }
    }
}

impl From<UpdateInteractionRequest> for interaction::ActiveModel {
    fn from(value: UpdateInteractionRequest) -> Self {
        Self {
            data: value.data.map(Set).unwrap_or_default(),
            ..Default::default()
        }
    }
}

pub(crate) fn interaction_from_model(
    interaction: interaction::Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Interaction {
    Interaction {
        id: interaction.id,
        created_date: interaction.created_date,
        last_modified: interaction.last_modified,
        data: interaction.data,
        organisation: Related::new(interaction.organisation_id, organisation_repository.clone()),
        nonce_id: interaction.nonce_id,
        interaction_type: interaction.interaction_type.into(),
        expires_at: interaction.expires_at,
    }
}
