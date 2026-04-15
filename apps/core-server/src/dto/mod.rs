use crate::dto::common::Boolean;

pub mod common;
pub mod error;
pub mod mapper;
pub mod response;

pub(crate) fn default_true() -> Boolean {
    Boolean::True
}
