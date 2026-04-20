use one_dto_mapper::From;
use shared_types::{WalletInstanceAttestedKeyId, WalletInstanceId};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;

use crate::model::revocation_list::{RevocationList, RevocationListRelations};

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct WalletInstanceAttestedKey {
    pub id: WalletInstanceAttestedKeyId,
    pub wallet_instance_id: WalletInstanceId, // cannot be a relation, because wallet instance defines a reverse relation already
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub public_key_jwk: PublicJwk,

    // Relations
    pub revocation: Option<WalletInstanceAttestedKeyRevocationInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletInstanceAttestedKeyRelations {
    pub revocation: Option<RevocationListRelations>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct WalletInstanceAttestedKeyRevocationInfo {
    pub revocation_list: RevocationList,
    pub revocation_list_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(WalletInstanceAttestedKey)]
pub struct WalletInstanceAttestedKeyUpsertRequest {
    pub id: WalletInstanceAttestedKeyId,
    pub wallet_instance_id: WalletInstanceId,
    pub expiration_date: OffsetDateTime,
    pub public_key_jwk: PublicJwk,
}
