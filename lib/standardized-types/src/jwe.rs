//! Spec: https://datatracker.ietf.org/doc/html/rfc7516

use serde::{Deserialize, Serialize};
use strum::Display;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Display)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum CompressionAlgorithm {
    /// Deflate: https://datatracker.ietf.org/doc/html/rfc1951
    DEF,
}
