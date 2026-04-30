use serde_json::json;
use shared_types::{OrganisationId, TrustCollectionId, VerifierInstanceId};

use crate::utils::api_clients::{HttpClient, Response};

pub struct VerifierIntanceApi {
    client: HttpClient,
}

#[derive(Debug)]
pub struct TestRegisterRequest {
    pub organisation_id: OrganisationId,
    pub provider_url: String,
    pub r#type: String,
}

impl VerifierIntanceApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn register_instance(&self, request: TestRegisterRequest) -> Response {
        let body = json!({
            "organisationId": request.organisation_id,
            "verifierProviderUrl": request.provider_url,
            "type": request.r#type
        });

        self.client.post("/api/verifier-instance/v1", body).await
    }

    pub async fn get_trust_collections(
        &self,
        verifier_instance_id: &VerifierInstanceId,
    ) -> Response {
        self.client
            .get(&format!(
                "/api/verifier-instance/v1/{verifier_instance_id}/trust-collections",
            ))
            .await
    }

    pub async fn patch_verifier_instance(
        &self,
        id: &VerifierInstanceId,
        trust_collections: Option<&[TrustCollectionId]>,
        trusted_issuer_required: Option<bool>,
    ) -> Response {
        let mut body = json!({});
        if let Some(trust_collections) = trust_collections {
            body["trustCollections"] = json!(trust_collections);
        }
        if let Some(trusted_issuer_required) = trusted_issuer_required {
            body["trustedIssuerRequired"] = json!(trusted_issuer_required);
        }

        self.client
            .patch(&format!("/api/verifier-instance/v1/{id}"), body)
            .await
    }
}
