use std::sync::Arc;

use itertools::Itertools;
use url::Url;

use super::VerificationProtocol;
use super::decorators::CapabilityChecked;
use super::iso_mdl::IsoMdl;
use super::openid4vp::draft20::OpenID4VP20HTTP;
use super::openid4vp::draft20_swiyu::{OpenID4VP20Swiyu, swiyu_to_draft20_params};
use super::openid4vp::final1_0::OpenID4VPFinal1_0;
use super::openid4vp::proximity_draft00::OpenID4VPProximityDraft00;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, VerificationProtocolType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::mqtt_client::MqttClient;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::session_provider::SessionProvider;
use crate::proto::trust_information::TrustInformationProvider;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait VerificationProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str)
    -> Result<Arc<dyn VerificationProtocol>, NestedError>;
    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)>;
}

#[async_trait::async_trait]
impl VerificationProtocolProvider
    for ProviderDirectory<String, Fields<VerificationProtocolType>, dyn VerificationProtocol>
{
    fn get_protocol(
        &self,
        protocol_id: &str,
    ) -> Result<Arc<dyn VerificationProtocol>, NestedError> {
        self.provider(protocol_id)
    }

    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)> {
        let get_order = |id: &String| {
            self.config(id)
                .ok()
                .and_then(|entry| entry.order)
                .unwrap_or(0)
        };
        let sorted_protocols = self
            .iter()
            .sorted_by(|(a, _), (b, _)| Ord::cmp(&get_order(a), &get_order(b)));

        sorted_protocols
            .into_iter()
            .find(|(_, protocol)| protocol.holder_can_handle(url))
            .map(|(id, protocol)| (id.to_owned(), protocol.to_owned()))
    }
}

#[expect(clippy::too_many_arguments)]
fn initialize_provider(
    name: &str,
    fields: &Fields<VerificationProtocolType>,
    core_config: &Arc<CoreConfig>,
    core_base_url: &Option<String>,
    credential_repository: &Arc<dyn CredentialRepository>,
    credential_schema_repository: &Arc<dyn CredentialSchemaRepository>,
    interaction_repository: &Arc<dyn InteractionRepository>,
    proof_repository: &Arc<dyn ProofRepository>,
    credential_formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: &Arc<dyn PresentationFormatterProvider>,
    key_provider: &Arc<dyn KeyProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    identifier_creator: &Arc<dyn IdentifierCreator>,
    ble: &Option<BleWaiter>,
    client: &Arc<dyn HttpClient>,
    openid_metadata_cache: &Arc<dyn OpenIDMetadataFetcher>,
    mqtt_client: &Option<Arc<dyn MqttClient>>,
    nfc_hce: &Option<Arc<dyn NfcHce>>,
    history_repository: &Arc<dyn HistoryRepository>,
    session_provider: &Arc<dyn SessionProvider>,
    wrp_validator: &Arc<dyn WRPValidator>,
    blob_storage_provider: &Arc<dyn BlobStorageProvider>,
    trust_information_provider: &Arc<dyn TrustInformationProvider>,
) -> Result<Arc<dyn VerificationProtocol>, InitializationError> {
    let protocol: Arc<dyn VerificationProtocol> = match fields.r#type {
        VerificationProtocolType::OpenId4VpFinal1_0 => Arc::new(OpenID4VPFinal1_0::new(
            name.to_owned(),
            core_base_url.clone(),
            credential_formatter_provider.clone(),
            presentation_formatter_provider.clone(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            certificate_validator.clone(),
            credential_repository.clone(),
            credential_schema_repository.clone(),
            history_repository.clone(),
            interaction_repository.clone(),
            session_provider.clone(),
            wrp_validator.clone(),
            blob_storage_provider.clone(),
            trust_information_provider.clone(),
            client.clone(),
            fields.merge_fields(),
            core_config.clone(),
        )?),
        VerificationProtocolType::OpenId4VpDraft20 => Arc::new(initialize_openid4vp_draft20(
            name.to_owned(),
            core_base_url.clone(),
            credential_formatter_provider.clone(),
            presentation_formatter_provider.clone(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            certificate_validator.clone(),
            credential_repository.clone(),
            interaction_repository.clone(),
            client.clone(),
            openid_metadata_cache.clone(),
            fields.merge_fields(),
            core_config.clone(),
        )?),
        VerificationProtocolType::OpenId4VpDraft20Swiyu => {
            let draft20_params = swiyu_to_draft20_params(fields.merge_fields()).map_err(|err| {
                InitializationError::InvalidParams {
                    key: name.to_string(),
                    source: err,
                }
            })?;
            let draft20 = initialize_openid4vp_draft20(
                name.to_owned(),
                core_base_url.clone(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                key_provider.clone(),
                certificate_validator.clone(),
                credential_repository.clone(),
                interaction_repository.clone(),
                client.clone(),
                openid_metadata_cache.clone(),
                draft20_params,
                core_config.clone(),
            )?;

            Arc::new(OpenID4VP20Swiyu::new(
                draft20,
                client.clone(),
                fields.merge_fields(),
            )?)
        }
        VerificationProtocolType::OpenId4VpProximityDraft00 => {
            Arc::new(OpenID4VPProximityDraft00::new(
                name.to_owned(),
                mqtt_client.clone(),
                core_config.clone(),
                fields.merge_fields(),
                credential_repository.clone(),
                credential_schema_repository.clone(),
                interaction_repository.clone(),
                proof_repository.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                did_method_provider.clone(),
                key_provider.clone(),
                certificate_validator.clone(),
                wrp_validator.clone(),
                identifier_creator.clone(),
                trust_information_provider.clone(),
                ble.clone(),
            )?)
        }
        VerificationProtocolType::IsoMdl => Arc::new(IsoMdl::new(
            name.to_owned(),
            core_config.clone(),
            credential_repository.clone(),
            presentation_formatter_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            credential_schema_repository.clone(),
            credential_formatter_provider.clone(),
            trust_information_provider.clone(),
            wrp_validator.clone(),
            ble.clone(),
            nfc_hce.clone(),
        )),
    };
    Ok(protocol)
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn verification_protocol_provider_from_config(
    config: &mut CoreConfig,
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ble: Option<BleWaiter>,
    client: Arc<dyn HttpClient>,
    openid_metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
    mqtt_client: Option<Arc<dyn MqttClient>>,
    nfc_hce: Option<Arc<dyn NfcHce>>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
    wrp_validator: Arc<dyn WRPValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    trust_information_provider: Arc<dyn TrustInformationProvider>,
) -> Result<Arc<dyn VerificationProtocolProvider>, ConfigValidationError> {
    let core_config = Arc::new(config.to_owned());

    let directory = ProviderDirectory::initialize(
        config.verification_protocol.iter_mut(),
        |name: &String, fields: &Fields<VerificationProtocolType>| {
            let provider = initialize_provider(
                name,
                fields,
                &core_config,
                &core_base_url,
                &credential_repository,
                &credential_schema_repository,
                &interaction_repository,
                &proof_repository,
                &credential_formatter_provider,
                &presentation_formatter_provider,
                &key_provider,
                &certificate_validator,
                &key_algorithm_provider,
                &did_method_provider,
                &identifier_creator,
                &ble,
                &client,
                &openid_metadata_cache,
                &mqtt_client,
                &nfc_hce,
                &history_repository,
                &session_provider,
                &wrp_validator,
                &blob_storage_provider,
                &trust_information_provider,
            )?;

            let provider: Arc<dyn VerificationProtocol> = Arc::new(CapabilityChecked {
                inner: provider,
                did_method_provider: did_method_provider.clone(),
            });

            Ok(provider)
        },
    )
    .error_while("initializing verification protocol providers")?;

    Ok(Arc::new(directory))
}

#[expect(clippy::too_many_arguments)]
fn initialize_openid4vp_draft20(
    config_id: String,
    core_base_url: Option<String>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    credential_repository: Arc<dyn CredentialRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    client: Arc<dyn HttpClient>,
    openid_metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
    params: serde_json::Value,
    config: Arc<CoreConfig>,
) -> Result<OpenID4VP20HTTP, InitializationError> {
    OpenID4VP20HTTP::new(
        config_id,
        core_base_url,
        credential_formatter_provider,
        presentation_formatter_provider,
        did_method_provider,
        key_algorithm_provider,
        key_provider,
        certificate_validator,
        credential_repository,
        interaction_repository,
        client,
        openid_metadata_cache,
        params,
        config,
    )
}
