use serde::Deserialize;

use crate::provider::data_type::DataType;
use crate::provider::data_type::error::DataTypeError;
use crate::provider::data_type::model::{
    CborType, DataTypeCapabilities, ExtractionResult, JsonType,
};

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub struct EnumValue {
    pub value: String,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub struct Params {
    pub values: Vec<EnumValue>,
}

pub struct EnumDataType {
    pub allowed_values: Vec<String>,
}

impl EnumDataType {
    pub fn new(params: Params) -> Self {
        Self {
            allowed_values: params.values.into_iter().map(|v| v.value).collect(),
        }
    }

    fn is_allowed(&self, value: &str) -> bool {
        self.allowed_values.iter().any(|v| v == value)
    }
}

impl DataType for EnumDataType {
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        Ok(match value {
            serde_json::Value::String(s) if self.is_allowed(s) => {
                ExtractionResult::Value(s.clone())
            }
            _ => ExtractionResult::NotApplicable,
        })
    }

    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        Ok(match value {
            ciborium::Value::Text(s) if self.is_allowed(s) => ExtractionResult::Value(s.clone()),
            _ => ExtractionResult::NotApplicable,
        })
    }

    fn get_capabilities(&self) -> DataTypeCapabilities {
        DataTypeCapabilities {
            supported_json_types: vec![JsonType::String],
            supported_cbor_types: vec![CborType::Text],
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    fn provider() -> EnumDataType {
        EnumDataType::new(Params {
            values: vec![
                EnumValue {
                    value: "urn:etsi:esi:eaa:eu:pub".to_string(),
                },
                EnumValue {
                    value: "urn:etsi:esi:eaa:eu:qualified".to_string(),
                },
            ],
        })
    }

    #[test]
    fn test_extract_json_allowed() {
        let dt = provider();
        let result = dt
            .extract_json_claim(&json!("urn:etsi:esi:eaa:eu:pub"))
            .unwrap();
        assert_eq!(
            result,
            ExtractionResult::Value("urn:etsi:esi:eaa:eu:pub".to_string())
        );
    }

    #[test]
    fn test_extract_json_not_allowed() {
        let dt = provider();
        let result = dt.extract_json_claim(&json!("unknown")).unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);
    }

    #[test]
    fn test_extract_cbor_allowed() {
        let dt = provider();
        let result = dt
            .extract_cbor_claim(&ciborium::Value::Text(
                "urn:etsi:esi:eaa:eu:qualified".to_string(),
            ))
            .unwrap();
        assert_eq!(
            result,
            ExtractionResult::Value("urn:etsi:esi:eaa:eu:qualified".to_string())
        );
    }

    #[test]
    fn test_extract_cbor_not_allowed() {
        let dt = provider();
        let result = dt
            .extract_cbor_claim(&ciborium::Value::Text("unknown".to_string()))
            .unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);
    }
}
