use std::sync::Arc;

use one_core::config::core_config::CoreConfig;
use proc_macros::modify_schema_autodetect;
use utoipa::openapi::extensions::Extensions;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{Contact, ExternalDocs, Object, Server, Tag};
use utoipa::{Modify, OpenApi};
use utoipauto::utoipauto;

pub(crate) mod permissions;
pub(crate) mod swagger_plugin;

use crate::build_info::{APP_VERSION, build};
use crate::openapi::permissions::PermissionsModifier;
use crate::{AuthMode, ServerConfig};

pub(crate) fn gen_openapi_documentation(
    server_config: Arc<ServerConfig>,
    core_config: Arc<CoreConfig>,
) -> utoipa::openapi::OpenApi {
    #[utoipauto(paths = "./apps/core-server/src", function_attribute_name = "endpoint")]
    #[derive(OpenApi)]
    #[openapi(components(schemas(shared_types::EntityId, shared_types::RevocationListId)))]
    struct ApiDoc;

    struct ApiDocModifier {
        config: Arc<ServerConfig>,
    }

    struct SecurityAddon {
        config: Arc<ServerConfig>,
    }

    impl Modify for ApiDocModifier {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if !self.config.enable_management_endpoints || !self.config.enable_external_endpoints {
                openapi.paths.paths.retain(|path, _| {
                    if path.starts_with("/ssi") || path.starts_with("/.well-known") {
                        return self.config.enable_external_endpoints;
                    }

                    if path.starts_with("/api") {
                        return self.config.enable_management_endpoints;
                    }

                    true
                });
            }
        }
    }

    impl Modify for SecurityAddon {
        #[expect(clippy::expect_used)]
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components = openapi.components.as_mut().expect("OpenAPI Components");
            match self.config.auth {
                AuthMode::UnsafeNone => {}
                AuthMode::UnsafeStatic { .. } | AuthMode::SecurityTokenService { .. } => {
                    components.add_security_scheme(
                        "bearer",
                        SecurityScheme::Http(
                            HttpBuilder::new()
                                .scheme(HttpAuthScheme::Bearer)
                                .description(Some("Local management access token"))
                                .build(),
                        ),
                    );
                }
            }
            components.add_security_scheme(
                "openID4VCI",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("OpenID4VCI token"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "remote-agent",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Remote Trust-entity owner access token"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "wallet-unit",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Wallet unit proof of authentication key possession."))
                        .build(),
                ),
            );
        }
    }

    let mut docs = ApiDoc::openapi();
    let modifier = ApiDocModifier {
        config: server_config.clone(),
    };
    modifier.modify(&mut docs);
    let security_addon = SecurityAddon {
        config: server_config.clone(),
    };
    security_addon.modify(&mut docs);

    PermissionsModifier.modify(&mut docs);

    CoreConfigModifier::new(core_config).modify(&mut docs);

    docs.info.title = "Procivis One Core API".into();
    docs.info.description = Some(indoc::formatdoc! {"
            The Procivis One Core API enables the full lifecycle of credentials.
        "});
    docs.info.version = APP_VERSION
        .unwrap_or(&format!(
            "UNTAGGED: {}, {}",
            build::SHORT_COMMIT,
            build::COMMIT_DATE_3339
        ))
        .to_string();
    docs.info.contact = Some(
        Contact::builder()
            .name(Some("Procivis One Docs"))
            .url(Some("https://www.procivis.ch/en/procivis-one#signup"))
            .build(),
    );
    docs.servers = Some(vec![
        Server::builder()
            .url("")
            .description(Some("Local server url"))
            .build(),
        Server::builder()
            .url("https://www.procivis-one.com")
            .description(Some("Generated server url"))
            .build(),
    ]);
    docs.tags = Some(get_tags(server_config));
    docs.external_docs = Some(
        ExternalDocs::builder()
            .url("https://docs.procivis.ch/")
            .description(Some("See the documentation"))
            .build(),
    );
    if let Some(l) = &mut docs.info.license {
        l.url = Some("https://github.com/procivis/one-core/blob/main/LICENSE".into());
        l.identifier = None;
    };

    docs
}

fn get_tags(config: Arc<ServerConfig>) -> Vec<Tag> {
    let mut tags = vec![
        Tag::builder()
            .name("other")
            .description(Some(indoc::formatdoc! {"
                System information and configuration. Use these endpoints to inspect
                your deployment's available components - credential formats, protocols,
                key algorithms, and many more - and to retrieve other system-level
                information.
            "}))
            .extensions(Some(
                Extensions::builder()
                    .add("x-displayName", "System Information")
                    .build(),
            ))
            .build(),
    ];

    if config.enable_management_endpoints {
        tags.append(&mut vec![
            Tag::builder()
                .name("organisation_management")
                .description(Some(indoc::formatdoc! {"
                The organization is the fundamental unit in Procivis One. All
                issuing, holding, and verifying actions are performed by an
                organization. Keys, DIDs, credentials, and proofs belong exclusively
                to the organization that created them.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Organizations")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("key")
                .description(Some(indoc::formatdoc! {"
                Manage cryptographic keys. Keys are the foundation of identifiers — used to
                create DIDs, certificates, and CAs, or as identifiers directly. Private keys
                are stored securely and never exposed through the API.

                Related guide: [Keys](https://docs.procivis.ch/keys)
            "}))
                .extensions(Some(
                    Extensions::builder().add("x-displayName", "Keys").build(),
                ))
                .build(),
            Tag::builder()
                .name("identifier_management")
                .description(Some(indoc::formatdoc! {"
                Create and manage identifiers of different types for different identity
                ecosystems. An identifier is needed to issue, hold, or verify.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Identifiers")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("certificate_management")
                .description(Some(indoc::formatdoc! {"
                Manage certificates in the system. To add a certificate as an identifier,
                see the Identifiers endpoints.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Certificates")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("did_management")
                .description(Some(indoc::formatdoc! {"
                Use the identifier API to create DIDs. The system assigns an ID to both
                the identifier and the DID. Use the DID ID returned from the identifier
                response with this DID API for management operations like deactivation.
            "}))
                .extensions(Some(
                    Extensions::builder().add("x-displayName", "DIDs").build(),
                ))
                .build(),
            Tag::builder()
                .name("credential_schema_management")
                .description(Some(indoc::formatdoc! {"
                A credential schema defines the structure and format of a credential,
                including the attributes that issuers make claims about. Schemas also
                specify how issued credentials should be presented in digital wallets,
                whether revocation methods are used, and issuer preferences for wallet
                storage type.

                The system supports the creation of as many credential schemas as needed.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Credential Schemas")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("credential_management")
                .description(Some(indoc::formatdoc! {"
                Issue credentials and manage the lifecycle of issued credentials, including
                suspension, reactivation, revocation and status check for holders and verifiers.

                Create a credential by specifying a schema and making claims about a subject.
                Then create a share endpoint URL for the wallet holder to access the offered
                credential. Suspension and revocation options are determined by the schema.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Credentials")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("proof_schema_management")
                .description(Some(indoc::formatdoc! {"
                Manage proof schemas, which define the claims requested from a holder during
                verification. A proof schema can combine claims from any number of credential
                schemas in your organization.

                Related guide: [Proof schemas](https://docs.procivis.ch/proof-schemas)
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Proof Schemas")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("proof_management")
                .description(Some(indoc::formatdoc! {"
                A proof request is a request of one or more claims from a wallet holder.

                Create a proof request then create a share endpoint URL for the holder
                to access the request. Any proof shared is verified.

                This resource also includes claim data deletion and presentation definition,
                a filtering function for wallet holders to see what credentials stored in
                their wallet match a proof request.

                Related guide: [Verify](https://docs.procivis.ch/verify)
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Proof Requests")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("interaction")
                .description(Some(indoc::formatdoc! {"
                For wallet agents, handle interactions with issuers and verifiers.

                When the holder scans the QR code offered by an issuer or a verifier, the
                handle invitation endpoint takes the encoded url and returns the interaction
                ID along with either the credential being offered or the proof being requested.

                The holder then makes the choice to accept or reject the exchange.

                Related guide: [Wallets](https://docs.procivis.ch/hold)
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Wallet Interaction")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("history_management")
                .description(Some(indoc::formatdoc! {"
                Manage and query the event history log. External services use this API
                to submit history entries to Core's centralized history service; all
                consumers use it to list or retrieve recorded events.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "History")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("wallet_instance")
                .description(Some(indoc::formatdoc! {"
                For Wallet Providers, manage wallet instances and attestations issued by the system.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Wallet Instances (Provider)")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("holder_wallet_instance")
                .description(Some(indoc::formatdoc! {"
                For wallet units, register with the Wallet Provider, check status and get trust information.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Wallet Instances (Holder)")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("verifier_instance")
                .description(Some(indoc::formatdoc! {"
                For verifier units, register with the Verifier Provider and get trust information.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Verifier Instances")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("signature")
                .description(Some(indoc::formatdoc! {"
                Create and revoke signatures.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Signatures")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("jsonld")
                .description(Some(indoc::formatdoc! {"
                Retrieve cached JSON-LD context documents.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "JSON-LD")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("task")
                .description(Some(indoc::formatdoc! {"
                Trigger configured maintenance and operational tasks.
                Tasks can also be run from the CLI or scheduled as cron
                jobs. See [Regular Tasks](https://docs.procivis.ch/reference/configuration/core#regular-tasks)
                for supported task types and their parameters.
            "}))
                .extensions(Some(
                    Extensions::builder().add("x-displayName", "Tasks").build(),
                ))
                .build(),
            Tag::builder()
                .name("cache")
                .description(Some(indoc::formatdoc! {"
                Manage the remote entity cache. See [Caching](https://docs.procivis.ch/configure/caching)
                for configuration.
            "}))
                .extensions(Some(
                    Extensions::builder().add("x-displayName", "Cache").build(),
                ))
                .build(),
            Tag::builder()
                .name("trust_list_publication_management")
                .description(Some(indoc::formatdoc! {"
                Publish and manage trust lists.        
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Trust List Publications")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("trust_collection_management")
                .description(Some(indoc::formatdoc! {"
                Manage collections of trust list subscriptions.
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Trust List Collections")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("statistics")
                .description(Some(indoc::formatdoc! {"
                Retrieve organizational and system statistics including issuance and
                verification counts, and active wallet unit counts. 
            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "Statistics")
                        .build(),
                ))
                .build(),
        ]);
    }
    if config.enable_external_endpoints {
        tags.append(&mut vec![
            Tag::builder()
                .name("ssi")
                .description(Some(indoc::formatdoc! {"

            :::warning

            These endpoints handle low-level mechanisms in interactions between agents.
            Deep understanding of the involved protocols is recommended.

            :::

        "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "(Advanced) SSI")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("openid4vci-final1_0")
                .description(Some(indoc::formatdoc! {"

                :::warning

                These endpoints handle low-level mechanisms in interactions between agents.
                Deep understanding of the involved protocols is recommended.

                :::

            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "(Advanced) OID4VCI Final 1.0")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("openid4vp-draft20")
                .description(Some(indoc::formatdoc! {"

                :::warning

                These endpoints handle low-level mechanisms in interactions between agents.
                Deep understanding of the involved protocols is recommended.

                :::

            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "(Advanced) OID4VP Draft 20")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("openid4vp-final-1.0")
                .description(Some(indoc::formatdoc! {"

                :::warning

                These endpoints handle low-level mechanisms in interactions between agents.
                Deep understanding of the involved protocols is recommended.

                :::

            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "(Advanced) OID4VP Final 1.0")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("openid4vci-final1_0-swiyu")
                .description(Some(indoc::formatdoc! {"

                :::warning

                These endpoints handle low-level mechanisms in interactions between agents.
                Deep understanding of the involved protocols is recommended.

                :::

            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "(Advanced) OID4VCI Final 1.0 - swiyu")
                        .build(),
                ))
                .build(),
            Tag::builder()
                .name("openid4vp-draft20-swiyu")
                .description(Some(indoc::formatdoc! {"

                :::warning

                These endpoints handle low-level mechanisms in interactions between agents.
                Deep understanding of the involved protocols is recommended.

                :::

            "}))
                .extensions(Some(
                    Extensions::builder()
                        .add("x-displayName", "(Advanced) OID4VP Draft 20 - swiyu")
                        .build(),
                ))
                .build(),
        ]);
    }
    tags
}

pub trait CoreConfigModifySchema {
    fn core_config_modify_schema(core_config: &CoreConfig, object: &mut Object);
}

#[modify_schema_autodetect(path = "apps/core-server/src")]
struct CoreConfigModifier {
    core_config: Arc<CoreConfig>,
}

impl CoreConfigModifier {
    fn new(core_config: Arc<CoreConfig>) -> Self {
        Self { core_config }
    }
}
