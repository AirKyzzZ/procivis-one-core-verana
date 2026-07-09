use std::convert::Infallible;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{impl_display, impl_from, impls_for_uuid_newtype};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct TransactionDataId(Uuid);

impls_for_uuid_newtype!(TransactionDataId);

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct TransactionDataType(String);

impl FromStr for TransactionDataType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<&str> for TransactionDataType {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for TransactionDataType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl_display!(TransactionDataType);
impl_from!(TransactionDataType; String);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;
#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(TransactionDataType);
#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(TransactionDataId);
