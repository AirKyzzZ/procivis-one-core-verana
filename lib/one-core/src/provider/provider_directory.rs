use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;

use thiserror::Error;

use crate::config::core_config::{ConfigFields, ConfigKey};
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::Provider;

pub trait WithDecorators {
    /// Should decorate:
    /// - disabled flag handling
    /// - common capability checks
    /// - provider level permission checks (if any)
    fn decorate(self: Arc<Self>, fields: &impl ConfigFields) -> Arc<Self>;
}

pub struct ProviderDirectory<C, CF, P>
where
    C: ConfigKey,
    CF: ConfigFields,
    P: Provider + ?Sized,
{
    providers: HashMap<C, Arc<P>>,
    configs: HashMap<C, CF>,
}

#[derive(Debug, Error)]
pub enum InitializationError {
    #[error("failed to deserialize params for config entry `{key}`: {source}")]
    InvalidParams {
        key: String,
        source: serde_json::Error,
    },
    #[error("Missing provider dependency: {0}")]
    MissingDependency(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for InitializationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidParams { .. } => ErrorCode::BR_0429,
            Self::MissingDependency(_) => ErrorCode::BR_0428,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ProviderDirectoryError {
    #[error("Missing provider `{config_key}` of type `{provider_type}`")]
    MissingProvider {
        config_key: String,
        provider_type: String,
    },
}

impl ErrorCodeMixin for ProviderDirectoryError {
    fn error_code(&self) -> ErrorCode {
        match self {
            ProviderDirectoryError::MissingProvider { .. } => ErrorCode::BR_0430,
        }
    }
}

impl<C, CF, P> ProviderDirectory<C, CF, P>
where
    C: ConfigKey,
    CF: ConfigFields,
    P: Provider + WithDecorators + ?Sized + 'static,
{
    pub fn initialize<'a, K>(
        config_blocks: impl Iterator<Item = (&'a C, &'a mut CF)>,
        initializer: impl Fn(&K, &CF) -> Result<Arc<P>, InitializationError>,
    ) -> Result<Self, InitializationError>
    where
        K: ?Sized,
        C: 'a + Borrow<K>,
        CF: 'a + ConfigFields,
    {
        let mut providers = HashMap::new();
        let mut configs = HashMap::new();

        for (config_id, field) in config_blocks {
            let provider = initializer(config_id.borrow(), field)?;
            let decorated = P::decorate(provider, field);
            configs.insert(config_id.clone(), field.clone());

            if let Some(capabilities) = decorated.capabilities() {
                field.set_capabilities(capabilities);
            }

            providers.insert(config_id.clone(), decorated);
        }

        Ok(Self { providers, configs })
    }

    pub fn provider<K>(&self, config_id: &K) -> Result<Arc<P>, NestedError>
    where
        K: Hash + Eq + ?Sized + Display,
        C: Borrow<K>,
    {
        self.providers.get(config_id).cloned().ok_or(
            ProviderDirectoryError::MissingProvider {
                config_key: config_id.to_string(),
                provider_type: std::any::type_name::<P>().to_string(),
            }
            .into(),
        )
    }

    pub fn iter(&self) -> impl Iterator<Item = (&C, &Arc<P>)> {
        self.providers.iter()
    }

    pub fn config(&self, config_id: &C) -> Result<&CF, NestedError> {
        self.configs.get(config_id).ok_or(
            ProviderDirectoryError::MissingProvider {
                config_key: config_id.to_string(),
                provider_type: std::any::type_name::<P>().to_string(),
            }
            .into(),
        )
    }

    pub fn iter_configs(&self) -> impl Iterator<Item = (&C, &CF)> {
        self.configs.iter()
    }
}
