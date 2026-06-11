use std::fmt::Display;

use shared_types::OrganisationId;

use super::{HttpClient, Response};

pub struct WalletUnitsApi {
    client: HttpClient,
}

pub struct ListFilters {
    pub organisation_id: OrganisationId,
    pub attestation: Option<String>,
    pub user_sub: Option<String>,
}

impl ListFilters {
    pub fn new(organisation_id: OrganisationId) -> Self {
        Self {
            organisation_id,
            attestation: None,
            user_sub: None,
        }
    }
}

impl WalletUnitsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn list(&self, list_filters: ListFilters) -> Response {
        let ListFilters {
            attestation,
            organisation_id,
            user_sub,
        } = list_filters;

        let mut url =
            format!("/api/wallet-instance/v1?organisationId={organisation_id}&page=0&pageSize=50");
        if let Some(attestation) = attestation {
            url += &format!("&attestation={attestation}");
        }
        if let Some(user_sub) = user_sub {
            url += &format!("&userSub={user_sub}");
        }

        self.client.get(&url).await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/wallet-instance/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn revoke(&self, id: &impl Display) -> Response {
        let url = format!("/api/wallet-instance/v1/{id}/revoke");
        self.client.post(&url, None).await
    }
}
