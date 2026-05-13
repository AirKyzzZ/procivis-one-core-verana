use std::convert::Infallible;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::macros::{impl_display, impl_from, impl_into};

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
/// Represents credential during transport (usually OpenID4VCI <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3-6.1.2.1>)
pub struct SerializedCredential(String);

impl FromStr for SerializedCredential {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<&str> for SerializedCredential {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for SerializedCredential {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl_display!(SerializedCredential);
impl_from!(SerializedCredential; String);
impl_into!(SerializedCredential; String);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;
#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(SerializedCredential);
