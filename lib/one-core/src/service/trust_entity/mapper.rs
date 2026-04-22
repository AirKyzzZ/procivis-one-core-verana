use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use shared_types::{DidValue, TrustEntityKey};
use uuid::Uuid;

use super::dto::{
    CreateTrustEntityFromDidPublisherRequestDTO, CreateTrustEntityParamsDTO,
    CreateTrustEntityRequestDTO, CreateTrustEntityTypeDTO, GetTrustEntityResponseDTO,
    TrustEntityCertificateResponseDTO, TrustEntityContent, TrustEntityFilterParamsDTO,
    TrustEntityFilterValue, UpdateTrustEntityActionFromDidRequestDTO,
    UpdateTrustEntityFromDidRequestDTO,
};
use super::error::TrustEntityServiceError;
use crate::model::certificate::CertificateState;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, StringMatch, StringMatchType, ValueComparison,
};
use crate::model::organisation::Organisation;
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{
    ExactTrustEntityFilterColumn, TrustEntity, TrustEntityState, TrustEntityType,
    UpdateTrustEntityRequest,
};
use crate::proto::certificate_validator::ParsedCertificate;
use crate::provider::trust_management::model::TrustEntityByEntityKey;
use crate::service::certificate::dto::CertificateX509AttributesDTO;

impl TryFrom<CreateTrustEntityRequestDTO>
    for (CreateTrustEntityTypeDTO, CreateTrustEntityParamsDTO)
{
    type Error = TrustEntityServiceError;

    fn try_from(value: CreateTrustEntityRequestDTO) -> Result<Self, Self::Error> {
        let key = match (
            value.r#type,
            value.did_id,
            value.identifier_id,
            value.content,
        ) {
            (Some(TrustEntityType::CertificateAuthority), None, None, Some(content)) => {
                CreateTrustEntityTypeDTO::Certificate(content)
            }
            (Some(TrustEntityType::Did), None, Some(identifier_id), None) => {
                CreateTrustEntityTypeDTO::Identifier(identifier_id)
            }
            (Some(TrustEntityType::Did), Some(did_id), None, None)
            | (None, Some(did_id), None, None) => CreateTrustEntityTypeDTO::Did(did_id),
            (None, _, _, _) => return Err(TrustEntityServiceError::TypeNotSpecified),
            (Some(_), _, _, _) => return Err(TrustEntityServiceError::AmbiguousIds),
        };
        let params = CreateTrustEntityParamsDTO {
            name: value.name,
            logo: value.logo,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role,
        };

        Ok((key, params))
    }
}

impl TryFrom<&ParsedCertificate> for TrustEntityKey {
    type Error = TrustEntityServiceError;
    fn try_from(value: &ParsedCertificate) -> Result<Self, Self::Error> {
        value
            .subject_key_identifier
            .clone()
            .ok_or(TrustEntityServiceError::MappingError(
                "missing subject key identifier".to_string(),
            ))
            .map(TrustEntityKey::from)
    }
}

pub(super) fn trust_entity_from_request(
    entity_key: TrustEntityKey,
    organisation: Organisation,
    content: Option<TrustEntityContent>,
    r#type: TrustEntityType,
    params: CreateTrustEntityParamsDTO,
    trust_anchor: TrustAnchor,
) -> TrustEntity {
    let id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();

    TrustEntity {
        id,
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        name: params.name,
        logo: convert_inner(params.logo),
        website: params.website,
        terms_url: params.terms_url,
        privacy_url: params.privacy_url,
        role: params.role,
        state: TrustEntityState::Active,
        r#type,
        entity_key,
        content,
        organisation: Some(organisation.into()),
        trust_anchor: trust_anchor.into(),
    }
}

pub(super) fn trust_entity_from_did_request(
    request: CreateTrustEntityFromDidPublisherRequestDTO,
    trust_anchor: TrustAnchor,
    did: DidValue,
) -> TrustEntity {
    let id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();

    TrustEntity {
        id,
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        name: request.name,
        logo: convert_inner(request.logo),
        website: request.website,
        terms_url: request.terms_url,
        privacy_url: request.privacy_url,
        role: request.role,
        state: TrustEntityState::Active,
        entity_key: (&did).into(),
        content: None,
        r#type: TrustEntityType::Did,
        trust_anchor: trust_anchor.into(),
        organisation: None,
    }
}

pub(super) async fn get_detail_trust_entity_response(
    trust_entity: TrustEntity,
    did: Option<Did>,
    identifier: Option<Identifier>,
    ca: Option<TrustEntityCertificateResponseDTO>,
) -> Result<GetTrustEntityResponseDTO, TrustEntityServiceError> {
    Ok(GetTrustEntityResponseDTO {
        id: trust_entity.id,
        created_date: trust_entity.created_date,
        last_modified: trust_entity.last_modified,
        name: trust_entity.name,
        logo: trust_entity.logo,
        website: trust_entity.website,
        terms_url: trust_entity.terms_url,
        privacy_url: trust_entity.privacy_url,
        role: trust_entity.role,
        trust_anchor: trust_entity
            .trust_anchor
            .get()
            .await
            .map_err(|err| TrustEntityServiceError::MappingError(err.to_string()))?
            .into(),
        state: trust_entity.state,
        organisation_id: trust_entity
            .organisation
            .as_ref()
            .map(|organisation| organisation.id()),
        did: did.map(Into::into),
        r#type: trust_entity.r#type,
        entity_key: trust_entity.entity_key,
        content: trust_entity.content,
        ca,
        identifier: identifier.map(Into::into),
    })
}

pub(super) fn trust_entity_certificate_from_x509(
    state: CertificateState,
    public_key: String,
    common_name: Option<String>,
    x509: CertificateX509AttributesDTO,
) -> TrustEntityCertificateResponseDTO {
    TrustEntityCertificateResponseDTO {
        state,
        common_name,
        public_key,
        serial_number: x509.serial_number,
        not_before: x509.not_before,
        not_after: x509.not_after,
        issuer: x509.issuer,
        subject: x509.subject,
        fingerprint: x509.fingerprint,
        extensions: x509.extensions,
    }
}

pub(super) fn update_request_from_dto(
    current_state: TrustEntityState,
    request: UpdateTrustEntityFromDidRequestDTO,
) -> Result<UpdateTrustEntityRequest, TrustEntityServiceError> {
    let new_state = match (request.action, current_state) {
        (Some(UpdateTrustEntityActionFromDidRequestDTO::Activate), TrustEntityState::Withdrawn) => {
            Some(TrustEntityState::Active)
        }
        (
            Some(UpdateTrustEntityActionFromDidRequestDTO::Activate),
            TrustEntityState::RemovedAndWithdrawn,
        ) => Some(TrustEntityState::Removed),

        (
            Some(UpdateTrustEntityActionFromDidRequestDTO::AdminActivate),
            TrustEntityState::Removed,
        ) => Some(TrustEntityState::Active),
        (
            Some(UpdateTrustEntityActionFromDidRequestDTO::AdminActivate),
            TrustEntityState::RemovedAndWithdrawn,
        ) => Some(TrustEntityState::Withdrawn),

        (Some(UpdateTrustEntityActionFromDidRequestDTO::Withdraw), TrustEntityState::Active) => {
            Some(TrustEntityState::Withdrawn)
        }
        (Some(UpdateTrustEntityActionFromDidRequestDTO::Withdraw), TrustEntityState::Removed) => {
            Some(TrustEntityState::RemovedAndWithdrawn)
        }

        (Some(UpdateTrustEntityActionFromDidRequestDTO::Remove), TrustEntityState::Active) => {
            Some(TrustEntityState::Removed)
        }
        (Some(UpdateTrustEntityActionFromDidRequestDTO::Remove), TrustEntityState::Withdrawn) => {
            Some(TrustEntityState::RemovedAndWithdrawn)
        }

        (None, _) => None,
        _ => {
            return Err(TrustEntityServiceError::InvalidUpdateRequest);
        }
    };

    Ok(UpdateTrustEntityRequest {
        state: new_state,
        logo: convert_inner_of_inner(request.logo),
        privacy_url: request.privacy_url,
        website: request.website,
        name: request.name,
        terms_url: request.terms_url,
        role: request.role,
        content: request.content,
    })
}

pub(super) fn trust_entity_from_identifier_and_anchor(
    trust_entity: TrustEntityByEntityKey,
    identifier: Identifier,
    trust_anchor: TrustAnchor,
    ca: Option<TrustEntityCertificateResponseDTO>,
) -> GetTrustEntityResponseDTO {
    GetTrustEntityResponseDTO {
        id: trust_entity.id,
        organisation_id: trust_entity.organisation_id,
        name: trust_entity.name,
        created_date: trust_entity.created_date,
        last_modified: trust_entity.last_modified,
        logo: trust_entity.logo,
        website: trust_entity.website,
        terms_url: trust_entity.terms_url,
        privacy_url: trust_entity.privacy_url,
        role: trust_entity.role,
        state: trust_entity.state,
        r#type: trust_entity.r#type,
        did: convert_inner(identifier.did.clone()),
        content: trust_entity.content,
        ca,
        trust_anchor: trust_anchor.into(),
        entity_key: trust_entity.entity_key,
        identifier: Some(identifier.into()),
    }
}

pub(super) fn trust_entity_from_partial_and_did_and_anchor(
    trust_entity: TrustEntityByEntityKey,
    did: Did,
    identifier: Option<Identifier>,
    trust_anchor: TrustAnchor,
) -> GetTrustEntityResponseDTO {
    let entity_key = (&did.did).into();
    GetTrustEntityResponseDTO {
        id: trust_entity.id,
        organisation_id: trust_entity.organisation_id,
        name: trust_entity.name,
        created_date: trust_entity.created_date,
        last_modified: trust_entity.last_modified,
        logo: trust_entity.logo,
        website: trust_entity.website,
        terms_url: trust_entity.terms_url,
        privacy_url: trust_entity.privacy_url,
        role: trust_entity.role,
        state: trust_entity.state,
        r#type: trust_entity.r#type,
        did: Some(did.into()),
        content: None,
        ca: None,
        trust_anchor: trust_anchor.into(),
        entity_key,
        identifier: identifier.map(Into::into),
    }
}

impl From<TrustEntityFilterParamsDTO> for ListFilterCondition<TrustEntityFilterValue> {
    fn from(filter: TrustEntityFilterParamsDTO) -> Self {
        let exact = filter.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = filter.name.map(|name| {
            TrustEntityFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactTrustEntityFilterColumn::Name),
                value: name,
            })
        });

        let role = filter.role.map(TrustEntityFilterValue::Role);

        let did_id = filter.did_id.map(TrustEntityFilterValue::DidId);

        let trust_anchor = filter.trust_anchor.map(TrustEntityFilterValue::TrustAnchor);

        let organisation_id = filter
            .organisation_id
            .map(TrustEntityFilterValue::OrganisationId);

        let types = filter.types.map(TrustEntityFilterValue::Types);

        let states = filter.states.map(TrustEntityFilterValue::States);

        let entity_key = filter.entity_key.map(TrustEntityFilterValue::EntityKey);

        let created_date_after = filter.created_date_after.map(|date| {
            TrustEntityFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });

        let created_date_before = filter.created_date_before.map(|date| {
            TrustEntityFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = filter.last_modified_after.map(|date| {
            TrustEntityFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });

        let last_modified_before = filter.last_modified_before.map(|date| {
            TrustEntityFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        ListFilterCondition::<TrustEntityFilterValue>::from(did_id)
            & trust_anchor
            & name
            & role
            & organisation_id
            & types
            & states
            & entity_key
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
