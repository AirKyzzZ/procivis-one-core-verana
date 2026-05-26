use super::error::DidServiceError;
use crate::model::did::Did;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::model::Operation;

pub(super) fn validate_deactivation_request(
    did: &Did,
    did_method: &dyn DidMethod,
    deactivate: bool,
) -> Result<(), DidServiceError> {
    if did.did_type.is_remote() {
        return Err(DidServiceError::RemoteDid);
    }

    if deactivate
        && !did_method
            .get_capabilities()
            .operations
            .contains(&Operation::DEACTIVATE)
    {
        return Err(DidServiceError::CannotBeDeactivated {
            method: did.did_method.to_owned(),
        });
    }

    if !deactivate {
        return Err(DidServiceError::CannotBeReactivated {
            method: did.did_method.to_owned(),
        });
    }

    if deactivate == did.deactivated {
        return Err(DidServiceError::DeactivatedSameValue {
            value: did.deactivated,
            method: did.did_method.to_owned(),
        });
    }

    Ok(())
}
