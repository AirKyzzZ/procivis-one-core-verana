use std::ops::Sub;
use std::sync::Arc;

use one_core::model::organisation::Organisation;
use one_core::model::wallet_instance::{
    GetWalletInstanceList, UpdateWalletInstanceRequest, WalletInstance, WalletInstanceListQuery,
    WalletInstanceOs, WalletInstanceRelations, WalletInstanceStatus, WalletProviderType,
};
use one_core::model::wallet_instance_attested_key::WalletInstanceAttestedKey;
use one_core::repository::wallet_instance_repository::WalletInstanceRepository;
use shared_types::WalletInstanceId;
use standardized_types::jwk::PublicJwk;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub struct WalletInstancesDB {
    repository: Arc<dyn WalletInstanceRepository>,
}

#[derive(Default)]
pub struct TestWalletInstance {
    pub id: Option<WalletInstanceId>,
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub last_modified: Option<OffsetDateTime>,
    pub public_key: Option<PublicJwk>,
    pub status: Option<WalletInstanceStatus>,
    pub last_issuance: Option<Option<OffsetDateTime>>,
    pub attested_keys: Option<Vec<WalletInstanceAttestedKey>>,
}

impl WalletInstancesDB {
    pub fn new(repository: Arc<dyn WalletInstanceRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        test_wallet_instance: TestWalletInstance,
    ) -> WalletInstance {
        let six_hours_ago = one_core::clock::now_utc().sub(Duration::days(1));

        let wallet_instance = WalletInstance {
            id: test_wallet_instance
                .id
                .unwrap_or_else(|| Uuid::new_v4().into()),
            name: test_wallet_instance
                .name
                .unwrap_or("test_wallet".to_string()),
            created_date: six_hours_ago,
            last_modified: test_wallet_instance.last_modified.unwrap_or(six_hours_ago),
            os: WalletInstanceOs::Android,
            status: test_wallet_instance
                .status
                .unwrap_or(WalletInstanceStatus::Active),
            wallet_provider_type: WalletProviderType::ProcivisOne,
            wallet_provider_name: "PROCIVIS_ONE".to_string(),
            authentication_key_jwk: test_wallet_instance.public_key,
            last_issuance: test_wallet_instance
                .last_issuance
                .unwrap_or(Some(six_hours_ago)),
            nonce: test_wallet_instance.nonce,
            trusted_rp_required: false,
            organisation: Some(organisation),
            attested_keys: test_wallet_instance.attested_keys,
        };

        self.repository
            .create_wallet_instance(wallet_instance.clone())
            .await
            .unwrap();

        wallet_instance
    }

    pub async fn list(&self, query: WalletInstanceListQuery) -> GetWalletInstanceList {
        self.repository
            .get_wallet_instance_list(query)
            .await
            .unwrap()
    }

    pub async fn get(
        &self,
        wallet_instance_id: impl Into<WalletInstanceId>,
        relations: &WalletInstanceRelations,
    ) -> Option<WalletInstance> {
        self.repository
            .get_wallet_instance(&wallet_instance_id.into(), relations)
            .await
            .unwrap()
    }

    pub async fn update(
        &self,
        wallet_instance_id: impl Into<WalletInstanceId>,
        request: UpdateWalletInstanceRequest,
    ) -> () {
        self.repository
            .update_wallet_instance(&wallet_instance_id.into(), request)
            .await
            .unwrap()
    }
}
