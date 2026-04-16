use one_core::provider::verification_protocol::dto::ApplicableCredentialOrFailureHintEnum;
use one_dto_mapper::try_convert_inner;

use super::dto::ApplicableCredentialOrFailureHintRestEnum;
use crate::mapper::MapperError;

impl TryFrom<ApplicableCredentialOrFailureHintEnum> for ApplicableCredentialOrFailureHintRestEnum {
    type Error = MapperError;

    fn try_from(value: ApplicableCredentialOrFailureHintEnum) -> Result<Self, Self::Error> {
        Ok(match value {
            ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
                applicable_credentials,
                purpose,
            } => Self::ApplicableCredentials {
                applicable_credentials: try_convert_inner(applicable_credentials)?,
                purpose,
            },
            ApplicableCredentialOrFailureHintEnum::FailureHint { failure_hint } => {
                Self::FailureHint {
                    failure_hint: Box::new((*failure_hint).into()),
                }
            }
        })
    }
}
