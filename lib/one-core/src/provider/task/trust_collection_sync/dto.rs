use serde::Deserialize;
use shared_types::{HolderWalletInstanceId, VerifierInstanceId};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum Params {
    HolderWalletUnitId(HolderWalletInstanceId),
    VerifierInstanceId(VerifierInstanceId),
}
