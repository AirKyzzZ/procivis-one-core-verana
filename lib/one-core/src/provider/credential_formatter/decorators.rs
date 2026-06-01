use std::fmt::Display;
use std::sync::Arc;

use shared_types::{CredentialFormat, CredentialSchemaId, OrganisationId, SerializedCredential};
use time::Duration;

use super::error::FormatterError;
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential,
    FormatterCapabilities, TokenVerifier,
};
use super::{CredentialFormatter, MetadataClaimSchema};
use crate::config::core_config::{KeyAlgorithmType, RevocationType};
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::provider::Provider;
use crate::provider::credential_formatter::CredentialSchemaVersion;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::key_selection::SelectedKey;

impl WithDisabledDecorator for dyn CredentialFormatter {
    fn decorate(self: Arc<dyn CredentialFormatter>) -> Arc<dyn CredentialFormatter> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + CredentialFormatter + Display + ?Sized> CredentialFormatter
    for DisabledProvider<T>
{
    async fn format_credential(
        &self,
        _credential_data: CredentialData,
        _auth_fn: AuthenticationFn,
    ) -> Result<SerializedCredential, FormatterError> {
        self.disabled_error()
    }

    async fn format_status_list<'a>(
        &self,
        _revocation_list_url: String,
        _issuer: SelectedKey<'a>,
        _encoded_list: String,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: RevocationType,
    ) -> Result<String, FormatterError> {
        self.disabled_error()
    }

    async fn extract_credentials<'a>(
        &self,
        credentials: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<DetailCredential, FormatterError> {
        self.inner()
            .extract_credentials(credentials, credential_schema, verification)
            .await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        self.inner()
            .extract_credentials_unverified(credential, credential_schema)
            .await
    }

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        self.inner().prepare_selective_disclosure(credential).await
    }

    fn get_leeway(&self) -> Duration {
        self.inner().get_leeway()
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        self.inner().get_capabilities()
    }

    fn credential_schema_id<'a>(
        &self,
        id: CredentialSchemaId,
        organisation_id: OrganisationId,
        schema_id: Option<&'a str>,
        core_base_url: &'a str,
        version: CredentialSchemaVersion,
        format: Option<&'a CredentialFormat>,
    ) -> Result<String, FormatterError> {
        self.inner().credential_schema_id(
            id,
            organisation_id,
            schema_id,
            core_base_url,
            version,
            format,
        )
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        self.inner().get_metadata_claims()
    }

    fn user_claims_path(&self) -> Vec<String> {
        self.inner().user_claims_path()
    }

    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<Credential, FormatterError> {
        self.inner()
            .parse_credential(credential, organisation, verification)
            .await
    }

    fn config_name(&self) -> &CredentialFormat {
        self.inner().config_name()
    }
}
