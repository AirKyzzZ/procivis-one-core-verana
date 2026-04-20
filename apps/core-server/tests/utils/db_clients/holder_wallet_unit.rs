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

pub struct HolderWalletUnitsDB {
    repository: Arc<dyn HolderWalletInstanceRepository>,
}

#[derive(Default)]
pub struct TestHolderWalletUnitParams {
    pub status: Option<WalletInstanceStatus>,
    pub wallet_provider_type: Option<WalletProviderType>,
    pub wallet_provider_name: Option<String>,
    pub wallet_provider_url: Option<String>,
    pub provider_wallet_unit_id: Option<WalletInstanceId>,
}

impl HolderWalletUnitsDB {
    pub fn new(repository: Arc<dyn HolderWalletInstanceRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        authentication_key: Option<Key>,
        test_holder_wallet_unit: TestHolderWalletUnitParams,
    ) -> HolderWalletInstance {
        let wallet_unit = CreateHolderWalletInstanceRequest {
            id: Uuid::new_v4().into(),
            status: test_holder_wallet_unit
                .status
                .unwrap_or(WalletInstanceStatus::Active),
            wallet_provider_type: test_holder_wallet_unit
                .wallet_provider_type
                .unwrap_or(WalletProviderType::ProcivisOne),
            wallet_provider_name: test_holder_wallet_unit
                .wallet_provider_name
                .unwrap_or("PROCIVIS_ONE".to_string()),
            wallet_provider_url: test_holder_wallet_unit
                .wallet_provider_url
                .unwrap_or("https://wallet.provider".to_string()),
            organisation,
            authentication_key,
            provider_wallet_unit_id: test_holder_wallet_unit
                .provider_wallet_unit_id
                .unwrap_or(Uuid::new_v4().into()),
        };

        let id = self
            .repository
            .create_holder_wallet_instance(wallet_unit)
            .await
            .unwrap();

        self.repository
            .get_holder_wallet_instance(&id, &HolderWalletInstanceRelations::default())
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn get(
        &self,
        wallet_unit_id: impl Into<HolderWalletInstanceId>,
        relations: &HolderWalletInstanceRelations,
    ) -> Option<HolderWalletInstance> {
        self.repository
            .get_holder_wallet_instance(&wallet_unit_id.into(), relations)
            .await
            .unwrap()
    }
}
