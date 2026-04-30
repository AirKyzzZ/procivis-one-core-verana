use std::sync::Arc;

use one_core::model::holder_wallet_instance::{
    CreateHolderWalletInstanceRequest, HolderWalletInstance, HolderWalletInstanceRelations,
};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::wallet_instance::{WalletInstanceStatus, WalletProviderType};
use one_core::repository::holder_wallet_instance_repository::HolderWalletInstanceRepository;
use shared_types::{HolderWalletInstanceId, WalletInstanceId};
use uuid::Uuid;

pub struct HolderWalletInstancesDB {
    repository: Arc<dyn HolderWalletInstanceRepository>,
}

#[derive(Default)]
pub struct TestHolderWalletInstanceParams {
    pub status: Option<WalletInstanceStatus>,
    pub wallet_provider_type: Option<WalletProviderType>,
    pub wallet_provider_name: Option<String>,
    pub wallet_provider_url: Option<String>,
    pub provider_wallet_unit_id: Option<WalletInstanceId>,
    pub trusted_rp_required: Option<bool>,
}

impl HolderWalletInstancesDB {
    pub fn new(repository: Arc<dyn HolderWalletInstanceRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        authentication_key: Option<Key>,
        test_holder_wallet_instance: TestHolderWalletInstanceParams,
    ) -> HolderWalletInstance {
        let wallet_instance = CreateHolderWalletInstanceRequest {
            id: Uuid::new_v4().into(),
            status: test_holder_wallet_instance
                .status
                .unwrap_or(WalletInstanceStatus::Active),
            wallet_provider_type: test_holder_wallet_instance
                .wallet_provider_type
                .unwrap_or(WalletProviderType::ProcivisOne),
            wallet_provider_name: test_holder_wallet_instance
                .wallet_provider_name
                .unwrap_or("PROCIVIS_ONE".to_string()),
            wallet_provider_url: test_holder_wallet_instance
                .wallet_provider_url
                .unwrap_or("https://wallet.provider".to_string()),
            organisation,
            authentication_key,
            provider_wallet_unit_id: test_holder_wallet_instance
                .provider_wallet_unit_id
                .unwrap_or(Uuid::new_v4().into()),
            trusted_rp_required: test_holder_wallet_instance
                .trusted_rp_required
                .unwrap_or_default(),
        };

        let id = self.repository.create(wallet_instance).await.unwrap();

        self.repository
            .get(&id, &HolderWalletInstanceRelations::default())
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn get(
        &self,
        id: impl Into<HolderWalletInstanceId>,
        relations: &HolderWalletInstanceRelations,
    ) -> Option<HolderWalletInstance> {
        self.repository.get(&id.into(), relations).await.unwrap()
    }
}
