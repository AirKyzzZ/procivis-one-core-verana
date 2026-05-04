use crate::error::ContextWithErrorCode;
use crate::model::credential::{Clearable, Credential, UpdateCredentialRequest};
use crate::proto::credential_validity_manager::{
    CredentialValidityCheckResult, CredentialValidityManagerImpl, Error,
};

impl CredentialValidityManagerImpl {
    pub(crate) async fn update_mdoc(
        &self,
        credential: &Credential,
        force_refresh: bool,
    ) -> Result<CredentialValidityCheckResult, Error> {
        let current_state = credential.state;
        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&credential.protocol)
            .ok_or(Error::MissingIssuanceProtocol(credential.protocol.clone()))?;
        let new_state = protocol
            .holder_refresh_credential(credential, force_refresh)
            .await
            .error_while("refreshing credential")?;

        if new_state != current_state {
            let update_request = UpdateCredentialRequest {
                state: Some(new_state),
                suspend_end_date: Clearable::DontTouch,
                ..Default::default()
            };

            self.credential_repository
                .update_credential(credential.id, update_request)
                .await
                .error_while("updating credential")?;
        }

        Ok(CredentialValidityCheckResult {
            credential_id: credential.id,
            status: new_state,
            success: true,
            reason: None,
        })
    }
}
