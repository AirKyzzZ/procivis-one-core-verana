use crate::config::core_config::DatatypeType;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;

pub(super) fn to_swiyu_data_type(
    data_type: DatatypeType,
    array: bool,
) -> Result<Option<String>, IssuanceProtocolError> {
    let data_type = match data_type {
        DatatypeType::Object | DatatypeType::Array => return Ok(None),
        // Swiyu handling of data and booleans is different in the iOS and Android wallets so it is
        // declared as string.
        DatatypeType::String | DatatypeType::Date | DatatypeType::Boolean => "string",
        DatatypeType::Number => "numeric",
        DatatypeType::SwiyuPicture => "image/jpeg",
        _ => {
            return Err(IssuanceProtocolError::Failed(format!(
                "Unsupported data type: {data_type:?}"
            )));
        }
    };

    if array {
        Ok(Some(format!("{data_type}[]")))
    } else {
        Ok(Some(data_type.to_string()))
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_to_swiyu_data_type_skips_container_claims() {
        assert_eq!(
            to_swiyu_data_type(DatatypeType::Object, false).unwrap(),
            None
        );
        assert_eq!(
            to_swiyu_data_type(DatatypeType::Array, false).unwrap(),
            None
        );
    }

    #[test]
    fn test_to_swiyu_data_type_marks_leaf_arrays() {
        assert_eq!(
            to_swiyu_data_type(DatatypeType::String, true).unwrap(),
            Some("string[]".to_string())
        );
        assert_eq!(
            to_swiyu_data_type(DatatypeType::Number, true).unwrap(),
            Some("numeric[]".to_string())
        );
    }
}
