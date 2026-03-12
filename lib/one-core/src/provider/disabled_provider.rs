use std::fmt::Display;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt, NestedError};
use crate::provider::Provider;

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
        Err(DisabledProviderError::Disabled(self.inner.to_string())
            .error_while("using provider")
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

#[derive(Debug, Error)]
pub enum DisabledProviderError {
    #[error("{0} is disabled")]
    Disabled(String),
}

impl ErrorCodeMixin for DisabledProviderError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0431
    }
}
