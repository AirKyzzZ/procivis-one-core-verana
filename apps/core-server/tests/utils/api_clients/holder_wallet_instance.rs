use serde_json::json;
use shared_types::{HolderWalletInstanceId, OrganisationId, TrustCollectionId};

use crate::utils::api_clients::{HttpClient, Response};

pub struct HolderWalletInstancesApi {
    client: HttpClient,
}

#[derive(Debug, Default)]
pub struct TestHolderRegisterRequest {
    pub organization_id: Option<OrganisationId>,
    pub wallet_provider_url: Option<String>,
    pub wallet_provider_type: Option<String>,
    pub key_type: Option<String>,
}

impl HolderWalletInstancesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn holder_get_wallet_instance_details(
        &self,
        wallet_unit_id: &HolderWalletInstanceId,
    ) -> Response {
        self.client
            .get(&format!(
                "/api/holder-wallet-instance/v1/{}",
                wallet_unit_id
            ))
            .await
    }

    pub async fn holder_get_wallet_instance_trust_collections(
        &self,
        wallet_unit_id: &HolderWalletInstanceId,
    ) -> Response {
        self.client
            .get(&format!(
                "/api/holder-wallet-instance/v1/{}/trust-collections",
                wallet_unit_id
            ))
            .await
    }

    pub async fn holder_register(&self, request: TestHolderRegisterRequest) -> Response {
        let body = json!(
            {
            "organisationId": request.organization_id,
            "walletProvider": {
                "url": request.wallet_provider_url.unwrap_or("http://localhost:3000".to_string()),
                "type": request.wallet_provider_type.unwrap_or("PROCIVIS_ONE".to_string()),
            },
            "keyType": request.key_type.unwrap_or("ECDSA".to_string()),
            }
        );

        self.client
            .post("/api/holder-wallet-instance/v1", body)
            .await
    }

    pub async fn holder_wallet_instance_status(
        &self,
        wallet_unit_id: &HolderWalletInstanceId,
    ) -> Response {
        self.client
            .post(
                &format!("/api/holder-wallet-instance/v1/{}/status", wallet_unit_id),
                None,
            )
            .await
    }

    pub async fn holder_wallet_instance_edit(
        &self,
        wallet_unit_id: &HolderWalletInstanceId,
        trust_collections: Option<&[TrustCollectionId]>,
        trusted_rp_required: Option<bool>,
    ) -> Response {
        let mut body = json!({});
        if let Some(trust_collections) = trust_collections {
            body["trustCollections"] = json!(trust_collections);
        }
        if let Some(trusted_rp_required) = trusted_rp_required {
            body["trustedRpRequired"] = json!(trusted_rp_required);
        }
        self.client
            .patch(
                &format!("/api/holder-wallet-instance/v1/{wallet_unit_id}"),
                body,
            )
            .await
    }
}
