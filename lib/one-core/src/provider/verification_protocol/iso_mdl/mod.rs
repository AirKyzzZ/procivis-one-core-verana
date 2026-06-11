//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ble::ISO_MDL_FLOW;
use ble_holder::{MdocBleHolderInteractionData, send_mdl_response};
use common::{DeviceRequest, to_cbor};
use futures::future::BoxFuture;
use proc_macros::Provider;
use serde_json::Value;
use url::Url;

use super::dto::{
    FormattedCredentialPresentation, InvitationResponseDTO, PresentationDefinitionFieldDTO,
    PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use super::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocol, VerificationProtocolError,
};
use crate::config::core_config::{
    CoreConfig, DidType, IdentifierType, TransportType, VerificationEngagement,
};
use crate::error::ContextWithErrorCode;
use crate::mapper::{NESTED_CLAIM_MARKER, decode_cbor_base64};
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::proto::bluetooth_low_energy::ble_resource::{Abort, BleWaiter};
use crate::proto::nfc::NfcError;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::trust_information::TrustInformationProvider;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, FormatPresentationCtx, FormattedPresentation,
};
use crate::provider::presentation_formatter::mso_mdoc::model::{
    DeviceResponse, DeviceResponseVersion, DocumentError,
};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::SessionTranscript;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::deserialize_interaction_data;
use crate::provider::verification_protocol::openid4vp::dcql::get_presentation_definition_v2;
use crate::provider::verification_protocol::openid4vp::mapper::format_to_type;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::credential::dto::CredentialAttestationBlobs;
use crate::service::credential::mapper::{
    credential_detail_response_from_model, get_remaining_batch_item_count,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;

mod ble;
pub(crate) mod ble_holder;
pub(crate) mod ble_verifier;
pub(crate) mod common;
pub(crate) mod device_engagement;
pub(crate) mod nfc;
mod session;

#[cfg(test)]
mod test;
mod verify_proof;

#[derive(Provider)]
pub(crate) struct IsoMdl {
    config_id: String,
    config: Arc<CoreConfig>,
    credential_repository: Arc<dyn CredentialRepository>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    trust_information_provider: Arc<dyn TrustInformationProvider>,
    ble: Option<BleWaiter>,
    nfc_hce: Option<Arc<dyn NfcHce>>,
}

impl IsoMdl {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: String,
        config: Arc<CoreConfig>,
        credential_repository: Arc<dyn CredentialRepository>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        trust_information_provider: Arc<dyn TrustInformationProvider>,
        ble: Option<BleWaiter>,
        nfc_hce: Option<Arc<dyn NfcHce>>,
    ) -> Self {
        Self {
            config_id,
            config,
            credential_repository,
            presentation_formatter_provider,
            key_provider,
            key_algorithm_provider,
            credential_schema_repository,
            credential_formatter_provider,
            trust_information_provider,
            ble,
            nfc_hce,
        }
    }
}

#[async_trait]
impl VerificationProtocol for IsoMdl {
    fn holder_can_handle(&self, _url: &Url) -> bool {
        false
    }

    async fn holder_handle_invitation(
        &self,
        _url: Url,
        _organisation: Organisation,
        _transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        unimplemented!()
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let ble = self.ble.as_ref().ok_or(VerificationProtocolError::Failed(
            "Missing BLE waiter".to_string(),
        ))?;

        let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let device_request_bytes = &interaction_data
            .session
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "interaction_session_data missing".to_string(),
            ))?
            .device_request_bytes;

        let device_request: DeviceRequest = ciborium::from_reader(device_request_bytes.as_slice())
            .context("device request deserialization error")
            .map_err(VerificationProtocolError::Other)?;

        let mut document_error = DocumentError::new();
        for doc_request in device_request.doc_requests {
            let doc_type = doc_request.items_request.into_inner().doc_type;
            document_error.insert(doc_type, 0);
        }
        let device_response = DeviceResponse {
            version: DeviceResponseVersion::V1_0,
            documents: None,
            document_errors: Some(vec![document_error]),
            status: 0,
        };

        send_mdl_response(ble, device_response, interaction_data).await?;

        Ok(())
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        let ble = self.ble.clone().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE central for submit proof".to_string())
        })?;

        let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let session = interaction_data.session.as_ref().ok_or_else(|| {
            VerificationProtocolError::Failed("invalid interaction data".to_string())
        })?;

        let credential_presentation =
            credential_presentations
                .first()
                .ok_or(VerificationProtocolError::Failed(
                    "no credentials to format".into(),
                ))?;

        let auth_fn = self.key_provider.get_signature_provider(
            &credential_presentation.key,
            credential_presentation.jwk_key_id.to_owned(),
            self.key_algorithm_provider.clone(),
        )?;

        let holder_did = credential_presentation
            .holder_did
            .as_ref()
            .map(|did| did.did.to_owned());

        let presentation_schema_format = credential_presentation.credential_schema.format().await?;
        let format_type = self
            .config
            .format
            .get_type(&presentation_schema_format)
            .error_while("getting format type")?;
        let (_, presentation_formatter) = self
            .presentation_formatter_provider
            .get_presentation_formatter_by_type(format_type)
            .ok_or(VerificationProtocolError::Failed(format!(
                "unknown format: {presentation_schema_format}"
            )))?;
        let session_transcript_bytes: EmbeddedCbor<SessionTranscript> =
            ciborium::from_reader(session.session_transcript_bytes.as_slice())?;

        let ctx = FormatPresentationCtx {
            mdoc_session_transcript: Some(to_cbor(session_transcript_bytes.inner())?),
            ..Default::default()
        };

        let mut presentations = Vec::with_capacity(credential_presentations.len());
        for credential in credential_presentations {
            let credential_format = format_to_type(&credential, &self.config).await?;
            presentations.push(CredentialToPresent {
                credential_token: credential.presentation,
                credential_format,
            });
        }

        let FormattedPresentation { vp_token, .. } = presentation_formatter
            .format_presentation(presentations, auth_fn, &holder_did, ctx)
            .await
            .error_while("formatting presentation")?;

        let device_response = decode_cbor_base64(&vp_token).error_while("decoding vp_token")?;

        send_mdl_response(&ble, device_response, interaction_data).await?;

        Ok(UpdateResponse { update_proof: None })
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let ble = self.ble.as_ref().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE interface".to_string())
        })?;

        // There is one shared flowId for both holder and verifier logic.
        // So this call cancels either one, if it is running
        ble.abort(Abort::Flow(*ISO_MDL_FLOW)).await;

        // explicitly stop NFC HCE if running
        if proof.role == ProofRole::Holder && proof.state == ProofStateEnum::Pending {
            let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
                proof
                    .interaction
                    .as_ref()
                    .and_then(|interaction| interaction.data.as_ref()),
            )?;

            if interaction_data
                .engagement
                .contains(&VerificationEngagement::NFC)
            {
                match self
                    .nfc_hce
                    .as_ref()
                    .ok_or_else(|| {
                        VerificationProtocolError::Failed("Missing NFC HCE interface".to_string())
                    })?
                    .stop_hosting(false)
                    .await
                {
                    Ok(_) | Err(NfcError::NotStarted) => {}
                    Err(err) => tracing::error!("Failed to stop NFC hosting: {err}"),
                }
            }
        }

        Ok(())
    }

    async fn verifier_share_proof(
        &self,
        _proof: &Proof,
        _format_to_type_mapper: FormatMapper,
        _type_to_descriptor: TypeToDescriptorMapper,
        _callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        unimplemented!()
    }

    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: serde_json::Value,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        let interaction_data: MdocBleHolderInteractionData =
            serde_json::from_value(interaction_data)?;

        let device_request_bytes = interaction_data
            .session
            .ok_or_else(|| VerificationProtocolError::Failed("Missing device_request".to_string()))?
            .device_request_bytes;

        let device_request: DeviceRequest = ciborium::from_reader(device_request_bytes.as_slice())
            .context("device request deserialization error")
            .map_err(VerificationProtocolError::Other)?;

        let mut relevant_credentials = vec![];
        let mut requested_credentials = vec![];

        let organisation_id = interaction_data.organisation_id;

        for doc_request in device_request.doc_requests {
            let items_request = doc_request.items_request.into_inner();
            let schema_id = items_request.doc_type;
            let namespaces = items_request.name_spaces;

            let credentials: Vec<_> = super::mapper::get_presentation_credentials_by_schema_id(
                self.credential_repository.as_ref(),
                schema_id.to_owned(),
                organisation_id,
            )
            .await
            .error_while("getting presentation credentials")?;

            let mut fields: Vec<PresentationDefinitionFieldDTO> = namespaces
                .into_iter()
                .flat_map(|(namespace, data_elements)| {
                    data_elements.into_keys().map(move |element| {
                        let name = format!("{namespace}{NESTED_CLAIM_MARKER}{element}");

                        PresentationDefinitionFieldDTO {
                            id: name.clone(),
                            name: Some(name),
                            purpose: None,
                            required: Some(false),
                            key_map: HashMap::new(),
                        }
                    })
                })
                .collect();

            let mut applicable_credentials = vec![];

            for credential in credentials {
                let claims = credential.claims.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("Claims missing for credential".to_string())
                })?;

                let mut credential_claim_requested = false;
                for claim in claims {
                    let claim_schema = claim.schema.as_ref().ok_or_else(|| {
                        VerificationProtocolError::Failed(
                            "Claim is missing claim schema".to_string(),
                        )
                    })?;
                    let key = &claim_schema.key;

                    // iso-mdl only permits sharing of 2nd-level attributes
                    if let Some(field_description) = fields.iter_mut().find(|field| {
                        &field.id == key
                            || key.starts_with(&format!("{}{NESTED_CLAIM_MARKER}", field.id))
                    }) {
                        field_description
                            .key_map
                            .insert(credential.id, field_description.id.to_owned());

                        credential_claim_requested = true;
                    }
                }

                if credential_claim_requested {
                    applicable_credentials.push(credential.id);

                    let remaining_batch_item_count = get_remaining_batch_item_count(
                        &credential,
                        self.credential_repository.as_ref(),
                    )
                    .await
                    .error_while("getting remaining batch items")?;

                    let credential = credential_detail_response_from_model(
                        credential,
                        &self.config,
                        CredentialAttestationBlobs::default(),
                        None,
                        remaining_batch_item_count,
                        self.credential_repository.as_ref(),
                    )
                    .await
                    .error_while("creating credential detail")?;
                    relevant_credentials.push(credential);
                }
            }

            let credential_response = PresentationDefinitionRequestedCredentialResponseDTO {
                id: schema_id,
                name: None,
                purpose: None,
                multiple: None,
                fields,
                applicable_credentials,
                inapplicable_credentials: vec![],
            };

            requested_credentials.push(credential_response);
        }

        let request_group = PresentationDefinitionRequestGroupResponseDTO {
            id: proof.id.to_string(),
            name: None,
            purpose: None,
            rule: PresentationDefinitionRuleDTO {
                r#type: PresentationDefinitionRuleTypeEnum::All,
                min: None,
                max: None,
                count: None,
            },
            requested_credentials,
        };

        Ok(PresentationDefinitionResponseDTO {
            request_groups: vec![request_group],
            credentials: relevant_credentials,
        })
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        context: Value,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        let interaction_data: MdocBleHolderInteractionData = serde_json::from_value(context)?;

        let device_request_bytes = interaction_data
            .session
            .ok_or_else(|| VerificationProtocolError::Failed("Missing device_request".to_string()))?
            .device_request_bytes;

        let device_request: DeviceRequest = ciborium::from_reader(device_request_bytes.as_slice())
            .context("device request deserialization error")
            .map_err(VerificationProtocolError::Other)?;

        use dcql::{
            ClaimPath, ClaimQuery, CredentialFormat, CredentialMeta, CredentialQuery, DcqlQuery,
            PathSegment,
        };

        let mut credentials = Vec::with_capacity(device_request.doc_requests.len());
        for doc_request in device_request.doc_requests {
            let request = doc_request.items_request.into_inner();
            let mut claims = vec![];
            for (namespace, elements) in request.name_spaces {
                for (element, intent_to_retain) in elements {
                    claims.push(ClaimQuery {
                        id: None,
                        path: ClaimPath {
                            segments: vec![
                                PathSegment::PropertyName(namespace.to_owned()),
                                PathSegment::PropertyName(element),
                            ],
                        },
                        values: None,
                        required: Some(false),
                        intent_to_retain: Some(intent_to_retain),
                    });
                }
            }

            credentials.push(CredentialQuery {
                id: request.doc_type.to_owned().into(),
                format: CredentialFormat::MsoMdoc,
                meta: CredentialMeta::MsoMdoc {
                    doctype_value: request.doc_type,
                },
                claims: Some(claims),
                claim_sets: None,
                trusted_authorities: None,
                multiple: false,
                require_cryptographic_holder_binding: true,
            });
        }

        let dcql_query = DcqlQuery {
            credentials,
            credential_sets: None,
        };

        get_presentation_definition_v2(
            dcql_query,
            proof,
            &*self.credential_repository,
            &*self.credential_schema_repository,
            &*self.credential_formatter_provider,
            &*self.trust_information_provider,
            &self.config,
        )
        .await
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        VerificationProtocolCapabilities {
            features: vec![],
            supported_transports: vec![TransportType::Ble],
            did_methods: vec![DidType::Key, DidType::Jwk, DidType::Web],
            verifier_identifier_types: vec![IdentifierType::Did],
            supported_presentation_definition: vec![
                PresentationDefinitionVersion::V1,
                PresentationDefinitionVersion::V2,
            ],
        }
    }

    fn config_name(&self) -> &str {
        &self.config_id
    }
}
