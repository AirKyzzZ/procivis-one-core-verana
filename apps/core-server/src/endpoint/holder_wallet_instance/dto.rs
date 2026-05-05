use one_core::service::error::ServiceError;
use one_core::service::wallet_instance::dto;
use one_dto_mapper::{From, Into, TryFrom, TryInto, convert_inner, try_convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{HolderWalletInstanceId, OrganisationId, TrustCollectionId, WalletInstanceId};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::endpoint::ssi::wallet_provider::dto::ProviderTrustCollectionRestDTO;
use crate::endpoint::wallet_provider::dto::WalletInstanceStatusRestEnum;
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = dto::HolderRegisterWalletInstanceRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HolderRegisterWalletInstanceRequestRestDTO {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Wallet Provider details.
    #[try_into(infallible)]
    pub wallet_provider: WalletProviderRestDTO,
    /// Choose a key type and the system will generate a key to use for
    /// registration.
    #[try_into(infallible)]
    pub key_type: String,
    /// When true, the wallet will only interact with entities that can be
    /// verified as trusted. Requires the Wallet Provider to have the
    /// `trustEcosystemsEnabled` feature flag enabled.
    #[try_into(infallible)]
    #[serde(default)]
    pub trusted_rp_required: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::HolderWalletInstanceRegisterResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderRegisterWalletInstanceResponseRestDTO {
    pub id: HolderWalletInstanceId,
    pub status: WalletInstanceStatusRestEnum,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into, From)]
#[into(dto::WalletProviderDTO)]
#[from(dto::WalletProviderDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletProviderRestDTO {
    /// Full URL for the GET Wallet Provider metadata endpoint,
    /// for example: <domain>/ssi/wallet-provider/v1/<walletProvider>
    pub url: String,
    /// Choose the Wallet Provider implementation.
    pub r#type: WalletProviderTypeRestEnum,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[from(dto::WalletProviderType)]
#[into(dto::WalletProviderType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletProviderTypeRestEnum {
    ProcivisOne,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = dto::HolderWalletInstanceResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderWalletInstanceDetailRestDTO {
    #[try_from(infallible)]
    pub id: HolderWalletInstanceId,
    #[serde(serialize_with = "front_time")]
    #[try_from(infallible)]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[try_from(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub provider_wallet_unit_id: WalletInstanceId,
    #[try_from(infallible)]
    pub wallet_provider_url: String,
    #[try_from(infallible)]
    pub wallet_provider_type: WalletProviderTypeRestEnum,
    #[try_from(infallible)]
    pub wallet_provider_name: String,
    #[try_from(infallible)]
    pub status: WalletInstanceStatusRestEnum,
    #[try_from(with_fn = try_convert_inner)]
    pub authentication_key: Option<KeyListItemResponseRestDTO>,
    #[try_from(infallible)]
    pub trusted_rp_required: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::EditHolderWalletInstanceRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EditHolderWalletInstanceRequestRestDTO {
    /// The trust collections the wallet subscribes to, selected from those
    /// made available by the Wallet Provider. The wallet will evaluate trust
    /// against the lists contained in these collections. To keep subscribed
    /// collections in sync with the Wallet Provider, run the
    /// `TRUST_COLLECTION_SYNC` task.
    pub trust_collections: Option<Vec<TrustCollectionId>>,
    /// When true, the wallet will only interact with entities that can be
    /// verified as trusted. Requires the Wallet Provider to have the
    /// `trustEcosystemsEnabled` feature flag enabled.
    pub trusted_rp_required: Option<bool>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::TrustCollectionsDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustCollectionsDetailRestDTO {
    /// Trust collections available from the Wallet Provider.
    #[from(with_fn = convert_inner)]
    pub trust_collections: Vec<TrustCollectionInfoRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::TrustCollectionInfoDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustCollectionInfoRestDTO {
    /// When true, the wallet is subscribed to this trust collection.
    pub selected: bool,
    #[serde(flatten)]
    pub collection: ProviderTrustCollectionRestDTO,
}
