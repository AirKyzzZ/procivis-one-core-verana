// quick_xml cannot tag enums by attribute value, so Transform and
// XPathFilter round-trip through flat structs that match the XML shape.

use serde::{Deserialize, Serialize};

use super::{ENVELOPED_SIGNATURE, EXC_C14N, Transform, XPATH_FILTER2, XPathFilter2Op};
use crate::xades::INC_C14N;

#[derive(Serialize, Deserialize)]
pub(super) struct TransformRaw {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
    #[serde(
        rename = "XPath",
        alias = "dsig-filter2:XPath",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    xpath_filters: Vec<XPathFilterRaw>,
}

#[derive(Serialize, Deserialize)]
struct XPathFilterRaw {
    #[serde(rename = "@Filter")]
    filter: String,
    #[serde(rename = "$text")]
    xpath: String,
}

impl TryFrom<TransformRaw> for Transform {
    type Error = String;

    fn try_from(raw: TransformRaw) -> Result<Self, Self::Error> {
        match raw.algorithm.as_str() {
            ENVELOPED_SIGNATURE => Ok(Self::EnvelopedSignature),
            EXC_C14N => Ok(Self::ExcC14n),
            INC_C14N => Ok(Self::InclC14n),
            XPATH_FILTER2 => raw
                .xpath_filters
                .into_iter()
                .map(|f| match f.filter.as_str() {
                    "subtract" => Ok(XPathFilter2Op::Subtract(f.xpath)),
                    "union" => Ok(XPathFilter2Op::Union(f.xpath)),
                    "intersect" => Ok(XPathFilter2Op::Intersect(f.xpath)),
                    other => Err(format!("unsupported XPath Filter 2.0 operation: {other}")),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Self::XPathFilter2),
            other => Err(format!("unsupported transform algorithm: {other}")),
        }
    }
}

impl From<Transform> for TransformRaw {
    fn from(t: Transform) -> Self {
        match t {
            Transform::EnvelopedSignature => Self {
                algorithm: ENVELOPED_SIGNATURE.to_string(),
                xpath_filters: vec![],
            },
            Transform::ExcC14n => Self {
                algorithm: EXC_C14N.to_string(),
                xpath_filters: vec![],
            },
            Transform::InclC14n => Self {
                algorithm: INC_C14N.to_string(),
                xpath_filters: vec![],
            },
            Transform::XPathFilter2(ops) => Self {
                algorithm: XPATH_FILTER2.to_string(),
                xpath_filters: ops
                    .into_iter()
                    .map(|op| {
                        let (filter, xpath) = match op {
                            XPathFilter2Op::Subtract(x) => ("subtract", x),
                            XPathFilter2Op::Union(x) => ("union", x),
                            XPathFilter2Op::Intersect(x) => ("intersect", x),
                        };
                        XPathFilterRaw {
                            filter: filter.to_string(),
                            xpath,
                        }
                    })
                    .collect(),
            },
        }
    }
}
