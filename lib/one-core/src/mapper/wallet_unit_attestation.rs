use crate::model::wallet_instance_attestation::{
    UpdateWalletInstanceAttestationRequest, WalletInstanceAttestation,
};

impl From<WalletInstanceAttestation> for UpdateWalletInstanceAttestationRequest {
    fn from(value: WalletInstanceAttestation) -> Self {
        Self {
            expiration_date: Some(value.expiration_date),
            attestation: Some(value.attestation),
        }
    }
}
