use one_core::model::credential::{CredentialListIncludeEntityTypeEnum, SortableCredentialColumn};
use one_core::model::credential_schema::SortableCredentialSchemaColumn;
use one_core::model::did::SortableDidColumn;
use one_core::model::history::SortableHistoryColumn;
use one_core::model::identifier::SortableIdentifierColumn;
use one_core::model::proof::SortableProofColumn;
use one_core::model::proof_schema::SortableProofSchemaColumn;
use one_core::proto::bluetooth_low_energy::low_level::dto::DeviceInfo;
use one_core::provider::verification_protocol::dto::{
    ApplicableCredentialOrFailureHintEnum, PresentationDefinitionFieldDTO,
    PresentationDefinitionRequestedCredentialResponseDTO,
};
use one_core::service::common_dto::ListQueryDTO;
use one_core::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialFilterParamsDTO, CredentialListItemResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO,
};
use one_core::service::credential_schema::dto::{
    CredentialSchemaFilterParamsDTO, CredentialSchemaListIncludeEntityTypeEnum,
    CredentialSchemaListItemResponseDTO, ImportCredentialSchemaClaimSchemaDTO,
};
use one_core::service::did::dto::{
    CreateDidRequestDTO, CreateDidRequestKeysDTO, DidFilterParamsDTO,
};
use one_core::service::error::ServiceError;
use one_core::service::history::dto::{
    HistoryFilterParamsDTO, HistoryMetadataResponse, HistoryResponseDTO,
};
use one_core::service::identifier::dto::{
    CreateIdentifierDidRequestDTO, GetIdentifierListItemResponseDTO, IdentifierFilterParamsDTO,
};
use one_core::service::key::dto::KeyRequestDTO;
use one_core::service::organisation::dto::{
    CreateOrganisationRequestDTO, UpsertOrganisationRequestDTO,
};
use one_core::service::proof::dto::{
    CreateProofRequestDTO, ProofClaimValueDTO, ProofDetailResponseDTO, ProofFilterParamsDTO,
};
use one_core::service::proof_schema::dto::{
    ImportProofSchemaClaimSchemaDTO, ProofSchemaFilterParamsDTO,
};
use one_core::service::ssi_holder::dto::{HandleInvitationResultDTO, InitiateIssuanceRequestDTO};
use one_core::service::verifier_instance::dto::EditVerifierInstanceRequestDTO;
use one_core::service::wallet_instance::dto::{
    EditHolderWalletInstanceRequestDTO, TrustCollectionInfoDTO,
};
use one_dto_mapper::{convert_inner, convert_inner_of_inner, try_convert_inner};
use serde_json::json;
use shared_types::KeyId;
use time::OffsetDateTime;

use super::ble::DeviceInfoBindingDTO;
use super::credential::{
    ClaimBindingDTO, ClaimValueBindingDTO, CredentialDetailBindingDTO,
    CredentialListItemBindingDTO, CredentialListQueryBindingDTO, MdocMsoValidityResponseBindingDTO,
};
use super::credential_schema::{
    CredentialSchemaBindingDTO, ImportCredentialSchemaClaimSchemaBindingDTO,
};
use super::did::{DidListQueryBindingDTO, DidRequestBindingDTO, DidRequestKeysBindingDTO};
use super::history::{
    HistoryErrorMetadataBindingDTO, HistoryListItemBindingDTO, HistoryListQueryBindingDTO,
    HistoryMetadataBinding, MultiLangStringBindingDTO,
};
use super::identifier::{CreateIdentifierDidRequestBindingDTO, IdentifierListQueryBindingDTO};
use super::interaction::{HandleInvitationResponseBindingEnum, InitiateIssuanceRequestBindingDTO};
use super::key::KeyRequestBindingDTO;
use super::organisation::{
    CreateOrganisationRequestBindingDTO, UpsertOrganisationRequestBindingDTO,
};
use super::proof::{
    ApplicableCredentialOrFailureHintBindingEnum, CreateProofRequestBindingDTO,
    PresentationDefinitionFieldBindingDTO, PresentationDefinitionRequestedCredentialBindingDTO,
    PresentationDefinitionV2ClaimBindingDTO, PresentationDefinitionV2ClaimValueBindingDTO,
    PresentationDefinitionV2CredentialDetailBindingDTO, ProofListQueryBindingDTO,
    ProofRequestClaimValueBindingDTO, ProofResponseBindingDTO,
};
use super::proof_schema::ImportProofSchemaClaimSchemaBindingDTO;
use super::verifier_instance::EditVerifierInstanceRequestBindingDTO;
use super::wallet_unit::{EditHolderWalletUnitRequestBindingDTO, TrustCollectionInfoBindingDTO};
use crate::binding::credential_schema::CredentialSchemaListQueryBindingDTO;
use crate::binding::proof_schema::ListProofSchemasFiltersBindingDTO;
use crate::error::ErrorResponseBindingDTO;
use crate::utils::{
    TimestampFormat, into_id, into_id_opt, into_id_opt_vec, into_timestamp, into_timestamp_opt,
};

impl<IN: Into<ClaimBindingDTO>> From<CredentialDetailResponseDTO<IN>>
    for CredentialDetailBindingDTO
{
    fn from(value: CredentialDetailResponseDTO<IN>) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.map(|inner| inner.format_timestamp()),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer: value.issuer.map(Into::into),
            holder: value.holder.map(Into::into),
            state: value.state.into(),
            schema: value.schema.into(),
            claims: convert_inner(value.claims),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            interaction_id: value
                .interaction_id
                .map(|interaction_id| interaction_id.to_string()),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
            mdoc_mso_validity: value.mdoc_mso_validity.map(|inner| inner.into()),
            protocol: value.protocol,
            profile: value.profile,
            trust_information: convert_inner(value.trust_information),
        }
    }
}

impl From<MdocMsoValidityResponseDTO> for MdocMsoValidityResponseBindingDTO {
    fn from(value: MdocMsoValidityResponseDTO) -> Self {
        Self {
            expiration: value.expiration.format_timestamp(),
            next_update: value.next_update.format_timestamp(),
            last_update: value.last_update.format_timestamp(),
        }
    }
}

impl From<CredentialListItemResponseDTO> for CredentialListItemBindingDTO {
    fn from(value: CredentialListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: value.issuance_date.map(|inner| inner.format_timestamp()),
            last_modified: value.last_modified.format_timestamp(),
            revocation_date: value.revocation_date.map(|inner| inner.format_timestamp()),
            issuer: optional_identifier_id_string(value.issuer),
            state: value.state.into(),
            schema: value.schema.into(),
            role: value.role.into(),
            suspend_end_date: value
                .suspend_end_date
                .map(|suspend_end_date| suspend_end_date.format_timestamp()),
            protocol: value.protocol,
            profile: value.profile,
        }
    }
}

impl From<ProofDetailResponseDTO> for ProofResponseBindingDTO {
    fn from(value: ProofDetailResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            state: value.state.into(),
            last_modified: value.last_modified.format_timestamp(),
            proof_schema: convert_inner(value.schema),
            verifier: value.verifier.map(Into::into),
            protocol: value.protocol,
            transport: value.transport,
            engagement: value.engagement,
            redirect_uri: value.redirect_uri,
            proof_inputs: convert_inner(value.proof_inputs),
            retain_until_date: value.retain_until_date.map(|date| date.format_timestamp()),
            requested_date: value.requested_date.map(|date| date.format_timestamp()),
            completed_date: value.completed_date.map(|date| date.format_timestamp()),
            claims_removed_at: value.claims_removed_at.map(|date| date.format_timestamp()),
            role: value.role.into(),
            profile: value.profile,
            trust_information: convert_inner(value.trust_information),
        }
    }
}

impl From<DetailCredentialSchemaResponseDTO> for CredentialSchemaBindingDTO {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            format: value.format.to_string(),
            revocation_method: value.revocation_method.map(|v| v.to_string()),
            key_storage_security: convert_inner(value.key_storage_security),
            schema_id: value.schema_id,
            imported_source_url: value.imported_source_url,
            layout_type: convert_inner(value.layout_type),
            layout_properties: convert_inner(value.layout_properties),
            allow_suspension: value.allow_suspension,
            requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
            translations: value.translations.into(),
        }
    }
}

impl<T: Into<ClaimBindingDTO>> From<DetailCredentialClaimValueResponseDTO<T>>
    for ClaimValueBindingDTO
{
    fn from(value: DetailCredentialClaimValueResponseDTO<T>) -> Self {
        match value {
            DetailCredentialClaimValueResponseDTO::Boolean(value) => {
                ClaimValueBindingDTO::Boolean { value }
            }
            DetailCredentialClaimValueResponseDTO::Float(value) => {
                ClaimValueBindingDTO::Float { value }
            }
            DetailCredentialClaimValueResponseDTO::Integer(value) => {
                ClaimValueBindingDTO::Integer { value }
            }
            DetailCredentialClaimValueResponseDTO::String(value) => {
                ClaimValueBindingDTO::String { value }
            }
            DetailCredentialClaimValueResponseDTO::Nested(value) => ClaimValueBindingDTO::Nested {
                value: value.into_iter().map(|v| v.into()).collect(),
            },
        }
    }
}

impl From<HandleInvitationResultDTO> for HandleInvitationResponseBindingEnum {
    fn from(value: HandleInvitationResultDTO) -> Self {
        match value {
            HandleInvitationResultDTO::Credential {
                interaction_id,
                tx_code,
                key_storage_security_levels,
                key_algorithms,
                protocol,
                requires_wallet_instance_attestation,
            } => Self::CredentialIssuance {
                interaction_id: interaction_id.to_string(),
                tx_code: convert_inner(tx_code),
                protocol,
                key_storage_security_levels: convert_inner_of_inner(key_storage_security_levels),
                key_algorithms,
                requires_wallet_instance_attestation,
            },
            HandleInvitationResultDTO::AuthorizationCodeFlow {
                interaction_id,
                authorization_code_flow_url,
                protocol,
            } => Self::AuthorizationCodeFlow {
                interaction_id: interaction_id.to_string(),
                authorization_code_flow_url,
                protocol,
            },
            HandleInvitationResultDTO::ProofRequest {
                interaction_id,
                proof_id,
                protocol,
            } => Self::ProofRequest {
                interaction_id: interaction_id.to_string(),
                proof_id: proof_id.to_string(),
                protocol,
            },
        }
    }
}

impl TryFrom<KeyRequestBindingDTO> for KeyRequestDTO {
    type Error = ServiceError;
    fn try_from(request: KeyRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_id(&request.organisation_id)?,
            key_type: request.key_type,
            key_params: json!(request.key_params),
            name: request.name,
            storage_type: request.storage_type,
            storage_params: json!(request.storage_params),
        })
    }
}

impl TryFrom<DidRequestBindingDTO> for CreateDidRequestDTO {
    type Error = ServiceError;
    fn try_from(request: DidRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_id(&request.organisation_id)?,
            name: request.name,
            did_method: request.did_method,
            keys: request.keys.try_into()?,
            params: Some(json!(request.params)),
        })
    }
}

impl TryFrom<DidRequestKeysBindingDTO> for CreateDidRequestKeysDTO {
    type Error = ServiceError;
    fn try_from(request: DidRequestKeysBindingDTO) -> Result<Self, Self::Error> {
        let convert = |ids: Vec<String>| -> Result<Vec<KeyId>, Self::Error> {
            ids.iter().map(into_id).collect()
        };

        Ok(Self {
            authentication: convert(request.authentication)?,
            assertion_method: convert(request.assertion_method)?,
            key_agreement: convert(request.key_agreement)?,
            capability_invocation: convert(request.capability_invocation)?,
            capability_delegation: convert(request.capability_delegation)?,
        })
    }
}

fn convert_history_metadata(
    value: Option<HistoryMetadataResponse>,
) -> Option<HistoryMetadataBinding> {
    match value {
        None => None,
        Some(value) => match value {
            HistoryMetadataResponse::UnexportableEntities(value) => {
                Some(HistoryMetadataBinding::UnexportableEntities {
                    value: value.into(),
                })
            }
            HistoryMetadataResponse::ErrorMetadata(value) => {
                Some(HistoryMetadataBinding::ErrorMetadata {
                    value: HistoryErrorMetadataBindingDTO {
                        error_code: Into::<&'static str>::into(value.error_code).to_string(),
                        message: value.message,
                    },
                })
            }
            HistoryMetadataResponse::WalletUnitJWT(value) => {
                Some(HistoryMetadataBinding::WalletUnitJWT(value))
            }
            HistoryMetadataResponse::WalletRelyingParty(value) => {
                Some(HistoryMetadataBinding::WalletRelyingParty {
                    value: value.into(),
                })
            }
            // external metadata only used in REST API
            HistoryMetadataResponse::External(_) => None,
            HistoryMetadataResponse::TrustResolution(value) => {
                Some(HistoryMetadataBinding::TrustResolution {
                    value: value.into(),
                })
            }
        },
    }
}

impl From<standardized_types::etsi_119_602::MultiLangString> for MultiLangStringBindingDTO {
    fn from(value: standardized_types::etsi_119_602::MultiLangString) -> Self {
        Self {
            lang: value.lang,
            value: value.value,
        }
    }
}

impl From<HistoryResponseDTO> for HistoryListItemBindingDTO {
    fn from(value: HistoryResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            action: value.action.into(),
            name: value.name,
            entity_id: value.entity_id.map(|id| id.to_string()),
            entity_type: value.entity_type.into(),
            metadata: convert_history_metadata(value.metadata),
            organisation_id: value.organisation_id.map(|id| id.to_string()),
            target: value.target,
            user: value.user,
        }
    }
}

impl From<CredentialSchemaListItemResponseDTO> for CredentialSchemaBindingDTO {
    fn from(value: CredentialSchemaListItemResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            format: value.format.to_string(),
            imported_source_url: value.imported_source_url,
            revocation_method: value.revocation_method.map(|v| v.to_string()),
            key_storage_security: convert_inner(value.key_storage_security),
            schema_id: value.schema_id,
            layout_type: convert_inner(value.layout_type),
            layout_properties: convert_inner(value.layout_properties),
            allow_suspension: value.allow_suspension,
            requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
            translations: value.translations.into(),
        }
    }
}

impl TryFrom<CreateProofRequestBindingDTO> for CreateProofRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateProofRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_schema_id: into_id(value.proof_schema_id)?,
            verifier_did_id: into_id_opt(value.verifier_did_id)?,
            verifier_identifier_id: into_id_opt(value.verifier_identifier_id)?,
            protocol: value.protocol,
            redirect_uri: value.redirect_uri,
            verifier_key: into_id_opt(value.verifier_key)?,
            verifier_certificate: into_id_opt(value.verifier_certificate)?,
            iso_mdl_engagement: value.iso_mdl_engagement,
            transport: value.transport,
            profile: value.profile,
            engagement: value.engagement,
            webhook_destination_url: None,
        })
    }
}

impl TryFrom<ProofListQueryBindingDTO> for ListQueryDTO<SortableProofColumn, ProofFilterParamsDTO> {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ProofListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: ProofFilterParamsDTO {
                name: value.name,
                exact: convert_inner_of_inner(value.exact),
                states: convert_inner_of_inner(value.proof_states),
                roles: convert_inner_of_inner(value.proof_roles),
                ids: into_id_opt_vec(&value.ids)?,
                proof_schema_ids: into_id_opt_vec(&value.proof_schema_ids)?,
                verifier_ids: None,
                profiles: value.profiles,
                organisation_id: into_id(value.organisation_id)?,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
                requested_date_after: into_timestamp_opt(value.requested_date_after)?,
                requested_date_before: into_timestamp_opt(value.requested_date_before)?,
                completed_date_after: into_timestamp_opt(value.completed_date_after)?,
                completed_date_before: into_timestamp_opt(value.completed_date_before)?,
            },
            include: None,
        })
    }
}

impl TryFrom<ImportProofSchemaClaimSchemaBindingDTO> for ImportProofSchemaClaimSchemaDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ImportProofSchemaClaimSchemaBindingDTO) -> Result<Self, Self::Error> {
        let claims = value.claims.unwrap_or_default();
        Ok(Self {
            id: into_id(&value.id)?,
            requested: value.requested,
            required: value.required,
            key: value.key,
            data_type: value.data_type,
            claims: try_convert_inner(claims)?,
            array: value.array,
        })
    }
}

impl TryFrom<ImportCredentialSchemaClaimSchemaBindingDTO> for ImportCredentialSchemaClaimSchemaDTO {
    type Error = ServiceError;

    fn try_from(value: ImportCredentialSchemaClaimSchemaBindingDTO) -> Result<Self, Self::Error> {
        let claims = value.claims.unwrap_or_default();
        Ok(Self {
            id: into_id(&value.id)?,
            created_date: into_timestamp(&value.created_date)?,
            last_modified: into_timestamp(&value.last_modified)?,
            required: value.required,
            key: value.key,
            datatype: value.datatype,
            array: value.array,
            claims: try_convert_inner(claims)?,
            mapping: None,
        })
    }
}

impl From<DeviceInfoBindingDTO> for DeviceInfo {
    fn from(value: DeviceInfoBindingDTO) -> Self {
        Self::new(value.address, value.mtu)
    }
}

impl From<ProofClaimValueDTO> for ProofRequestClaimValueBindingDTO {
    fn from(value: ProofClaimValueDTO) -> Self {
        match value {
            ProofClaimValueDTO::Value(value) => Self::Value { value },
            ProofClaimValueDTO::Claims(claims) => ProofRequestClaimValueBindingDTO::Claims {
                value: convert_inner(claims),
            },
        }
    }
}

/// uniffi does not support double option.
/// workaround for `Option<Option<String>>`
#[derive(Clone, Debug, uniffi::Enum)]
pub enum OptionalString {
    None,
    Some { value: String },
}

impl From<OptionalString> for Option<String> {
    fn from(value: OptionalString) -> Self {
        match value {
            OptionalString::None => None,
            OptionalString::Some { value } => Some(value),
        }
    }
}

pub(crate) fn optional_time(value: Option<OffsetDateTime>) -> Option<String> {
    value.as_ref().map(TimestampFormat::format_timestamp)
}

impl TryFrom<HistoryListQueryBindingDTO>
    for ListQueryDTO<SortableHistoryColumn, HistoryFilterParamsDTO>
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: HistoryListQueryBindingDTO) -> Result<Self, Self::Error> {
        let (search_type, search_query) = match value.search {
            Some(s) => (convert_inner(s.r#type), Some(s.text)),
            None => (None, None),
        };

        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: HistoryFilterParamsDTO {
                organisation_ids: Some(vec![into_id(&value.organisation_id)?]),
                entity_ids: into_id_opt_vec(&value.entity_ids)?,
                entity_types: convert_inner_of_inner(value.entity_types),
                actions: convert_inner_of_inner(value.actions),
                identifier_id: into_id_opt(value.identifier_id)?,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                credential_id: into_id_opt(value.credential_id)?,
                credential_schema_id: into_id_opt(value.credential_schema_id)?,
                proof_id: into_id_opt(value.proof_id)?,
                proof_schema_id: into_id_opt(value.proof_schema_id)?,
                users: value.users,
                sources: None,
                search_query,
                search_type,
            },
            include: None,
        })
    }
}

pub(crate) fn optional_identifier_id_string(
    value: Option<GetIdentifierListItemResponseDTO>,
) -> Option<String> {
    value.map(|inner| inner.id.to_string())
}

impl TryFrom<CreateOrganisationRequestBindingDTO> for CreateOrganisationRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateOrganisationRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            id: into_id_opt(value.id)?,
            parent_organisation: into_id_opt(value.parent_organisation)?,
        })
    }
}

impl TryFrom<UpsertOrganisationRequestBindingDTO> for UpsertOrganisationRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: UpsertOrganisationRequestBindingDTO) -> Result<Self, Self::Error> {
        let wallet_provider_issuer = value
            .wallet_provider_issuer
            .map(Option::<String>::from)
            .map(into_id_opt)
            .transpose()?;

        let parent_organisation = value
            .parent_organisation
            .map(Option::<String>::from)
            .map(into_id_opt)
            .transpose()?;

        Ok(Self {
            id: into_id(&value.id)?,
            deactivate: value.deactivate,
            wallet_provider: convert_inner(value.wallet_provider),
            wallet_provider_issuer,
            parent_organisation,
        })
    }
}

impl TryFrom<CreateIdentifierDidRequestBindingDTO> for CreateIdentifierDidRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateIdentifierDidRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            method: value.method,
            keys: value.keys.try_into()?,
            params: Some(json!(value.params)),
        })
    }
}

impl From<PresentationDefinitionRequestedCredentialResponseDTO>
    for PresentationDefinitionRequestedCredentialBindingDTO
{
    fn from(value: PresentationDefinitionRequestedCredentialResponseDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
            purpose: value.purpose,
            multiple: value.multiple,
            fields: convert_inner(value.fields),
            applicable_credentials: value
                .applicable_credentials
                .iter()
                .map(|item| item.to_string())
                .collect(),
            inapplicable_credentials: value
                .inapplicable_credentials
                .iter()
                .map(|item| item.to_string())
                .collect(),
        }
    }
}

impl From<PresentationDefinitionFieldDTO> for PresentationDefinitionFieldBindingDTO {
    fn from(value: PresentationDefinitionFieldDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
            purpose: value.purpose,
            required: value.required.unwrap_or(true),
            key_map: value
                .key_map
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        }
    }
}

impl TryFrom<InitiateIssuanceRequestBindingDTO> for InitiateIssuanceRequestDTO {
    type Error = ServiceError;
    fn try_from(request: InitiateIssuanceRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: into_id(request.organisation_id)?,
            protocol: request.protocol,
            issuer: request.issuer,
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            scope: request.scope,
            authorization_details: convert_inner_of_inner(request.authorization_details),
            issuer_state: None,
            authorization_server: None,
        })
    }
}

impl<IN: Into<PresentationDefinitionV2ClaimBindingDTO>> From<CredentialDetailResponseDTO<IN>>
    for PresentationDefinitionV2CredentialDetailBindingDTO
{
    fn from(value: CredentialDetailResponseDTO<IN>) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            issuance_date: optional_time(value.issuance_date),
            revocation_date: optional_time(value.revocation_date),
            state: value.state.into(),
            last_modified: value.last_modified.format_timestamp(),
            schema: value.schema.into(),
            issuer: convert_inner(value.issuer),
            issuer_certificate: convert_inner(value.issuer_certificate),
            claims: convert_inner(value.claims),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            suspend_end_date: optional_time(value.suspend_end_date),
            mdoc_mso_validity: convert_inner(value.mdoc_mso_validity),
            holder: convert_inner(value.holder),
            protocol: value.protocol,
            profile: value.profile,
        }
    }
}

impl<T: Into<PresentationDefinitionV2ClaimBindingDTO>>
    From<DetailCredentialClaimValueResponseDTO<T>>
    for PresentationDefinitionV2ClaimValueBindingDTO
{
    fn from(value: DetailCredentialClaimValueResponseDTO<T>) -> Self {
        match value {
            DetailCredentialClaimValueResponseDTO::Boolean(value) => Self::Boolean { value },
            DetailCredentialClaimValueResponseDTO::Float(value) => Self::Float { value },
            DetailCredentialClaimValueResponseDTO::Integer(value) => Self::Integer { value },
            DetailCredentialClaimValueResponseDTO::String(value) => Self::String { value },
            DetailCredentialClaimValueResponseDTO::Nested(value) => Self::Nested {
                value: value.into_iter().map(|v| v.into()).collect(),
            },
        }
    }
}

impl From<ApplicableCredentialOrFailureHintEnum> for ApplicableCredentialOrFailureHintBindingEnum {
    fn from(value: ApplicableCredentialOrFailureHintEnum) -> Self {
        match value {
            ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
                applicable_credentials,
                purpose,
            } => Self::ApplicableCredentials {
                applicable_credentials: convert_inner(applicable_credentials),
                purpose: purpose.map(|p| p.0),
            },
            ApplicableCredentialOrFailureHintEnum::FailureHint { failure_hint } => {
                Self::FailureHint {
                    failure_hint: (*failure_hint).into(),
                }
            }
        }
    }
}

impl TryFrom<EditHolderWalletUnitRequestBindingDTO> for EditHolderWalletInstanceRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: EditHolderWalletUnitRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            trust_collections: value
                .trust_collections
                .map(|c| c.into_iter().map(into_id).collect::<Result<_, _>>())
                .transpose()?,
            trusted_rp_required: value.trusted_rp_required,
        })
    }
}

impl TryFrom<EditVerifierInstanceRequestBindingDTO> for EditVerifierInstanceRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: EditVerifierInstanceRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            trust_collections: value
                .trust_collections
                .map(|c| c.into_iter().map(into_id).collect::<Result<_, _>>())
                .transpose()?,
            trusted_issuer_required: value.trusted_issuer_required,
        })
    }
}

impl From<TrustCollectionInfoDTO> for TrustCollectionInfoBindingDTO {
    fn from(value: TrustCollectionInfoDTO) -> Self {
        Self {
            selected: value.selected,
            id: value.collection.id.to_string(),
            name: value.collection.name,
            logo: value.collection.logo,
            display_name: convert_inner(value.collection.display_name),
            description: convert_inner(value.collection.description),
        }
    }
}

impl TryFrom<IdentifierListQueryBindingDTO>
    for ListQueryDTO<SortableIdentifierColumn, IdentifierFilterParamsDTO>
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: IdentifierListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: IdentifierFilterParamsDTO {
                ids: into_id_opt_vec(&value.ids)?,
                name: value.name,
                types: convert_inner_of_inner(value.types),
                states: convert_inner_of_inner(value.states),
                did_methods: value.did_methods,
                is_remote: value.is_remote,
                key_algorithms: value.key_algorithms,
                key_roles: convert_inner_of_inner(value.key_roles),
                key_storages: value.key_storages,
                certificate_roles: convert_inner_of_inner(value.certificate_roles),
                certificate_roles_match_mode: convert_inner(value.certificate_roles_match_mode)
                    .unwrap_or_default(),
                trust_issuance_schema_id: into_id_opt(value.trust_issuance_schema_id)?,
                trust_verification_schema_id: into_id_opt(value.trust_verification_schema_id)?,
                exact: convert_inner_of_inner(value.exact),
                organisation_id: into_id(&value.organisation_id)?,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
            },
            include: None,
        })
    }
}

impl TryFrom<DidListQueryBindingDTO> for ListQueryDTO<SortableDidColumn, DidFilterParamsDTO> {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: DidListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: DidFilterParamsDTO {
                name: value.name,
                did: value.did,
                r#type: convert_inner(value.r#type),
                exact: convert_inner_of_inner(value.exact),
                deactivated: value.deactivated,
                key_algorithms: value.key_algorithms,
                key_roles: convert_inner_of_inner(value.key_roles),
                key_storages: value.key_storages,
                key_ids: into_id_opt_vec(&value.key_ids)?,
                did_methods: value.did_methods,
                organisation_id: into_id(&value.organisation_id)?,
            },
            include: None,
        })
    }
}

impl TryFrom<CredentialListQueryBindingDTO>
    for ListQueryDTO<
        SortableCredentialColumn,
        CredentialFilterParamsDTO,
        CredentialListIncludeEntityTypeEnum,
    >
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CredentialListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: CredentialFilterParamsDTO {
                organisation_id: into_id(&value.organisation_id)?,
                name: value.name,
                search_text: value.search_text,
                search_type: convert_inner_of_inner(value.search_type),
                exact: convert_inner_of_inner(value.exact),
                roles: convert_inner_of_inner(value.roles),
                ids: into_id_opt_vec(&value.ids)?,
                credential_schema_ids: into_id_opt_vec(&value.credential_schema_ids)?,
                issuers: None,
                states: convert_inner_of_inner(value.states),
                profiles: value.profiles,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
                issuance_date_after: into_timestamp_opt(value.issuance_date_after)?,
                issuance_date_before: into_timestamp_opt(value.issuance_date_before)?,
                revocation_date_after: into_timestamp_opt(value.revocation_date_after)?,
                revocation_date_before: into_timestamp_opt(value.revocation_date_before)?,
            },
            include: convert_inner_of_inner(value.include),
        })
    }
}

impl TryFrom<ListProofSchemasFiltersBindingDTO>
    for ListQueryDTO<SortableProofSchemaColumn, ProofSchemaFilterParamsDTO>
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: ListProofSchemasFiltersBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: ProofSchemaFilterParamsDTO {
                name: value.name,
                exact: convert_inner_of_inner(value.exact),
                organisation_id: into_id(value.organisation_id)?,
                ids: into_id_opt_vec(&value.ids)?,
                formats: value.formats,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
            },
            include: None,
        })
    }
}

impl TryFrom<CredentialSchemaListQueryBindingDTO>
    for ListQueryDTO<
        SortableCredentialSchemaColumn,
        CredentialSchemaFilterParamsDTO,
        CredentialSchemaListIncludeEntityTypeEnum,
    >
{
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CredentialSchemaListQueryBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            page: value.page,
            page_size: value.page_size,
            sort: convert_inner(value.sort),
            sort_direction: convert_inner(value.sort_direction),
            filter: CredentialSchemaFilterParamsDTO {
                name: value.name,
                exact: convert_inner_of_inner(value.exact),
                organisation_id: into_id(value.organisation_id)?,
                schema_id: value.schema_id,
                schema_ids: value.schema_ids,
                formats: value.formats,
                requires_wallet_instance_attestation: None,
                key_storage_security: None,
                credential_schema_ids: into_id_opt_vec(&value.ids)?,
                created_date_after: into_timestamp_opt(value.created_date_after)?,
                created_date_before: into_timestamp_opt(value.created_date_before)?,
                last_modified_after: into_timestamp_opt(value.last_modified_after)?,
                last_modified_before: into_timestamp_opt(value.last_modified_before)?,
                uses_batch_issuance: value.uses_batch_issuance,
                is_multiformat_schema: value.is_multiformat_schema,
            },
            include: value
                .include
                .map(|incl| incl.into_iter().map(Into::into).collect()),
        })
    }
}
