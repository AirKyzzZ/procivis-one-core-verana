use std::fmt::Display;
use std::sync::Arc;

use serde_json::Value;

use crate::error::NestedError;
use crate::provider::Provider;
use crate::provider::provider_directory::ProviderError;

pub struct DisabledProvider<T: Provider + Display + ?Sized> {
    inner: Arc<T>,
}

impl<T: Provider + Display + ?Sized> DisabledProvider<T> {
    pub fn new(inner: Arc<T>) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn disabled_error<V, E: From<NestedError>>(&self) -> Result<V, E> {
        Err(NestedError::from(ProviderError::ProviderDisabled {
            provider: self.inner.to_string(),
        })
        .into())
    }
}

impl<T: Provider + Display + ?Sized> Provider for DisabledProvider<T> {
    fn capabilities(&self) -> Option<Value> {
        self.inner.capabilities()
    }

    fn enabled(&self) -> bool {
        false
    }
}
