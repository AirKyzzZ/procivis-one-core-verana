use one_core::service::error::ServiceError;
use one_core::service::history::dto::CreateHistoryRequestDTO;

use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::history::dto::{CreateHistoryRequestRestDTO, HistoryEntityType};

const ORGANISATION_INDEPENDENT_ENTITIES: [HistoryEntityType; 6] = [
    HistoryEntityType::StsRole,
    HistoryEntityType::StsOrganisation,
    HistoryEntityType::StsIamRole,
    HistoryEntityType::StsSession,
    HistoryEntityType::StsToken,
    HistoryEntityType::User,
];

impl TryInto<CreateHistoryRequestDTO> for CreateHistoryRequestRestDTO {
    type Error = ServiceError;

    fn try_into(self) -> Result<CreateHistoryRequestDTO, Self::Error> {
        let organisation_id = match fallback_organisation_id_from_session(self.organisation_id) {
            Ok(organisation_id) => Some(organisation_id),
            Err(_) if ORGANISATION_INDEPENDENT_ENTITIES.contains(&self.entity_type) => None,
            Err(err) => return Err(err),
        };
        Ok(CreateHistoryRequestDTO {
            action: self.action.into(),
            name: self.name,
            entity_id: self.entity_id,
            entity_type: self.entity_type.into(),
            organisation_id,
            source: self.source.into(),
            target: self.target,
            metadata: self.metadata,
        })
    }
}
