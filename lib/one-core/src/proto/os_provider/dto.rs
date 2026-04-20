use one_dto_mapper::Into;
use strum::{Display, EnumString};

use crate::model::wallet_instance::WalletInstanceOs;

#[derive(Debug, Display, EnumString, Into, Clone, Copy)]
#[into(WalletInstanceOs)]
#[strum(ascii_case_insensitive, serialize_all = "UPPERCASE")]
pub enum OSName {
    Android,
    Ios,
    Web,
}
