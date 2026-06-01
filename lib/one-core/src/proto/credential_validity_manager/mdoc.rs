use super::{CredentialValidityCheckResult, CredentialValidityManagerImpl, Error};
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::credential::{
    Clearable, Credential, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;

impl CredentialValidityManagerImpl {
    pub(crate) async fn update_mdoc(
        &self,
        credential: &Credential,
        force_refresh: bool,
    ) -> Result<CredentialValidityCheckResult, Error> {
        let detail_credential = self.credential_to_detail_credential(credential).await?;

        if !force_refresh && !credential_requires_update(&detail_credential) {
            return Ok(CredentialValidityCheckResult {
                credential_id: credential.id,
                status: CredentialStateEnum::Accepted,
                success: true,
                reason: None,
            });
        }

        let interaction = credential
            .interaction
            .as_ref()
            .ok_or(Error::MappingError("Missing interaction".to_string()))?;

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&credential.protocol)?;

        let new_state = match protocol
            .holder_refresh_credential(interaction, Some(credential.id))
            .await
        {
            Ok(_) => CredentialStateEnum::Accepted,
            Err(IssuanceProtocolError::RefreshNotPossible)
                if credential_expired(&detail_credential) =>
            {
                CredentialStateEnum::Revoked
            }
            Err(err) => {
                tracing::warn!(%err, "Credential refresh failure");
                if credential_expired(&detail_credential) {
                    CredentialStateEnum::Suspended
                } else {
                    CredentialStateEnum::Accepted
                }
            }
        };

        if new_state != credential.state {
            self.credential_repository
                .update_credential(
                    credential.id,
                    UpdateCredentialRequest {
                        state: Some(new_state),
                        suspend_end_date: Clearable::DontTouch,
                        ..Default::default()
                    },
                )
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

    async fn credential_to_detail_credential(
        &self,
        credential: &Credential,
    ) -> Result<DetailCredential, Error> {
        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(Error::MappingError("schema is None".to_string()))?;

        let credential_bytes = if let Some(credential_blob_id) = credential.credential_blob_id {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;

            blob_storage
                .get(&credential_blob_id)
                .await
                .error_while("getting credential blob")?
                .ok_or(Error::MappingError("credential blob missing".to_string()))?
                .value
        } else {
            vec![]
        };
        let credential_str = String::from_utf8(credential_bytes)
            .map_err(|e| Error::MappingError(e.to_string()))?
            .into();

        let credential_schema_format = credential_schema.format().await?;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&credential_schema_format)?;

        let detail_credential = formatter
            .extract_credentials_unverified(&credential_str, Some(credential_schema))
            .await
            .error_while("extracting credential")?;
        Ok(detail_credential)
    }
}

fn credential_expired(detail_credential: &DetailCredential) -> bool {
    let now = crate::clock::now_utc();

    if let Some(valid_until) = detail_credential.valid_until {
        return valid_until < now;
    }

    false
}

fn credential_requires_update(detail_credential: &DetailCredential) -> bool {
    let now = crate::clock::now_utc();

    if let Some(valid_until) = detail_credential.update_at {
        return valid_until < now;
    }

    credential_expired(detail_credential)
}
