use proc_macros::Provider;

use super::KeySecurityLevel;
use super::dto::{KeySecurityLevelCapabilities, Params};
use crate::config::core_config::KeySecurityLevelType;
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;

#[derive(Provider)]
pub struct Moderate {
    params: Params,
}

impl KeySecurityLevel for Moderate {
    fn get_capabilities(&self) -> KeySecurityLevelCapabilities {
        KeySecurityLevelCapabilities {
            openid_security_level: vec![KeyStorageSecurityLevel::Moderate],
        }
    }
    fn get_priority(&self) -> u64 {
        self.params.holder.priority
    }

    fn get_key_storages(&self) -> &[String] {
        self.params.holder.key_storages.as_slice()
    }

    fn level(&self) -> KeySecurityLevelType {
        KeySecurityLevelType::Moderate
    }
}

impl Moderate {
    pub(crate) fn new(params: Params) -> Self {
        Self { params }
    }
}
