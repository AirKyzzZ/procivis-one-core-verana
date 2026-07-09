use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, InteractionId, OrganisationId, ProofId, TransactionDataId};

use crate::model::credential_schema::KeyStorageSecurity;
use crate::model::interaction::InteractionType;
use crate::provider::issuance_protocol::model::OpenID4VCITxCode;

#[derive(Clone, Debug)]
pub struct PresentationSubmitV2RequestDTO {
    pub interaction_id: InteractionId,
    pub submission: HashMap<String, Vec<PresentationSubmitV2CredentialRequestDTO>>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitV2CredentialRequestDTO {
    /// Submitted credential.
    pub credential_id: CredentialId,
    /// Path of claims that were optionally selected by the user.
    pub user_selections: Vec<String>,
    /// Optional ids of transaction-data entries to be included in the presentation of this credential.
    /// Entries not listed here are auto-assigned. Ids must reference transaction
    /// data applicable to this credential.
    pub transaction_data_ids: Vec<TransactionDataId>,
}

#[derive(Clone, Debug)]
pub enum HandleInvitationResultDTO {
    Credential {
        interaction_id: InteractionId,
        tx_code: Option<OpenID4VCITxCode>,
        key_storage_security_levels: Option<Vec<KeyStorageSecurity>>,
        key_algorithms: Option<Vec<String>>,
        protocol: String,
        requires_wallet_instance_attestation: bool,
    },
    AuthorizationCodeFlow {
        interaction_id: InteractionId,
        authorization_code_flow_url: String,
        protocol: String,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof_id: ProofId,
        protocol: String,
    },
}

#[derive(Clone, Debug)]
pub struct ContinueIssuanceResponseDTO {
    pub interaction_id: InteractionId,
    pub interaction_type: InteractionType,
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurity>>,
    pub key_algorithms: Option<Vec<String>>,
    pub requires_wallet_instance_attestation: bool,
    pub protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitiateIssuanceRequestDTO {
    pub organisation_id: OrganisationId,
    pub protocol: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<Vec<String>>,
    pub authorization_details: Option<Vec<InitiateIssuanceAuthorizationDetailDTO>>,
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitiateIssuanceAuthorizationDetailDTO {
    pub r#type: String,
    pub credential_configuration_id: String,
}

#[derive(Clone, Debug)]
pub struct InitiateIssuanceResponseDTO {
    pub interaction_id: InteractionId,
    pub url: String,
}

/// Interaction data stored on holder side for the OpenID Authorization code flow
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OpenIDAuthorizationCodeFlowInteractionData {
    pub request: InitiateIssuanceRequestDTO,
    pub code_verifier: Option<String>,
}
