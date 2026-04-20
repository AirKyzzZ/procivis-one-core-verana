use std::ops::Add;
use std::sync::Arc;

use one_core::model::key::Key;
use one_core::model::wallet_instance_attestation::{
    WalletInstanceAttestation, WalletInstanceAttestationRelations,
};
use one_core::repository::wallet_instance_attestation_repository::WalletInstanceAttestationRepository;
use shared_types::{HolderWalletInstanceId, WalletInstanceAttestationId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub struct WalletInstanceAttestationsDB {
    repository: Arc<dyn WalletInstanceAttestationRepository>,
}

#[derive(Default)]
pub struct TestWalletInstanceAttestation {
    pub id: Option<WalletInstanceAttestationId>,
    pub expiration_date: Option<OffsetDateTime>,
    pub attestation: Option<String>,
    pub revocation_list_url: Option<String>,
    pub revocation_list_index: Option<i64>,
}

impl WalletInstanceAttestationsDB {
    pub fn new(repository: Arc<dyn WalletInstanceAttestationRepository>) -> Self {
        Self { repository }
    }

    #[expect(unused)]
    pub async fn get_by_wallet_instance(
        &self,
        holder_wallet_instance_id: &HolderWalletInstanceId,
    ) -> Vec<WalletInstanceAttestation> {
        self.repository
            .get_wallet_instance_attestations_by_holder_wallet_unit(
                holder_wallet_instance_id,
                &WalletInstanceAttestationRelations::default(),
            )
            .await
            .unwrap()
    }

    #[expect(unused)]
    pub async fn create(
        &self,
        test_wallet_instance_attestation: TestWalletInstanceAttestation,
        holder_wallet_instance_id: HolderWalletInstanceId,
        attested_key: Key,
    ) -> WalletInstanceAttestation {
        let now = one_core::clock::now_utc();
        let attestation = WalletInstanceAttestation {
            id: test_wallet_instance_attestation
                .id
                .unwrap_or(Uuid::new_v4().into()),
            created_date: now,
            last_modified: now,
            expiration_date: test_wallet_instance_attestation
                .expiration_date
                .unwrap_or(now.add(Duration::minutes(180))),
            attestation: test_wallet_instance_attestation
                .attestation
                .unwrap_or("some_invalid_attestation".to_string()),
            holder_wallet_unit_id: holder_wallet_instance_id,
            revocation_list_url: test_wallet_instance_attestation.revocation_list_url,
            revocation_list_index: test_wallet_instance_attestation.revocation_list_index,
            attested_key: Some(attested_key),
        };
        self.repository
            .create_wallet_instance_attestation(attestation.clone())
            .await
            .unwrap();

        attestation
    }
}
