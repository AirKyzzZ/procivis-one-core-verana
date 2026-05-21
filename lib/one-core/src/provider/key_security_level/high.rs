use proc_macros::Provider;

use super::KeySecurityLevel;
use super::dto::{KeySecurityLevelCapabilities, Params};
use crate::config::core_config::KeySecurityLevelType;
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;

#[derive(Provider)]
pub struct High {
    params: Params,
}

impl KeySecurityLevel for High {
    fn get_capabilities(&self) -> KeySecurityLevelCapabilities {
        KeySecurityLevelCapabilities {
            openid_security_level: vec![KeyStorageSecurityLevel::High],
        }
    }
    fn get_priority(&self) -> u64 {
        self.params.holder.priority
    }

    fn get_key_storages(&self) -> &[String] {
        self.params.holder.key_storages.as_slice()
    }

    fn level(&self) -> KeySecurityLevelType {
        KeySecurityLevelType::High
    }
}

impl High {
    pub(crate) fn new(params: Params) -> Self {
        Self { params }
    }
}
