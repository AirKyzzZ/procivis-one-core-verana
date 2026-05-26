//! Implementation of keys validation of DIDs.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::model::key::Key;
use crate::provider::did_method::DidKeys;

#[derive(Debug, Serialize, Clone)]
pub struct MinMax<const N: usize> {
    pub min: usize,
    pub max: usize,
}

impl<const N: usize> MinMax<N> {
    fn contains(&self, number: usize) -> bool {
        self.min <= number && self.max >= number
    }
}

impl<const N: usize> Default for MinMax<N> {
    fn default() -> Self {
        Self { min: 1, max: 1 }
    }
}

impl<'a, const N: usize> Deserialize<'a> for MinMax<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        struct Proxy {
            min: usize,
            max: usize,
        }

        let val = Proxy::deserialize(deserializer)?;

        if val.min < N {
            return Err(serde::de::Error::custom(format!(
                "`min` cannot be smaller then {N}"
            )));
        }

        if val.max < val.min {
            return Err(serde::de::Error::custom(
                "`max` cannot be smaller then `min`",
            ));
        }

        Ok(MinMax {
            min: val.min,
            max: val.max,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Keys {
    #[serde(default, flatten)]
    pub global: MinMax<1>,
    #[serde(default)]
    pub authentication: MinMax<0>,
    #[serde(default)]
    pub assertion_method: MinMax<0>,
    #[serde(default)]
    pub key_agreement: MinMax<0>,
    #[serde(default)]
    pub capability_invocation: MinMax<0>,
    #[serde(default)]
    pub capability_delegation: MinMax<0>,
}

impl Keys {
    pub fn validate_keys(&self, keys: &DidKeys) -> bool {
        let global = count_uniq(
            keys.authentication
                .iter()
                .chain(&keys.assertion_method)
                .chain(&keys.key_agreement)
                .chain(&keys.capability_invocation)
                .chain(&keys.capability_delegation),
        );
        let authentication = count_uniq(&keys.authentication);
        let assertion_method = count_uniq(&keys.assertion_method);
        let key_agreement = count_uniq(&keys.key_agreement);
        let capability_invocation = count_uniq(&keys.capability_invocation);
        let capability_delegation = count_uniq(&keys.capability_delegation);

        self.global.contains(global)
            && self.authentication.contains(authentication)
            && self.assertion_method.contains(assertion_method)
            && self.key_agreement.contains(key_agreement)
            && self.capability_invocation.contains(capability_invocation)
            && self.capability_delegation.contains(capability_delegation)
    }
}

fn count_uniq<'a>(vec: impl IntoIterator<Item = &'a Key>) -> usize {
    vec.into_iter()
        .map(|key| key.id)
        .collect::<HashSet<_>>()
        .len()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::test_utilities::dummy_key;

    #[test]
    fn test_validate_keys_default() {
        let key = dummy_key();
        let keys = DidKeys {
            authentication: vec![key.clone()],
            assertion_method: vec![key.clone()],
            key_agreement: vec![key.clone()],
            capability_invocation: vec![key.clone()],
            capability_delegation: vec![key],
            update_keys: None,
        };
        assert!(Keys::default().validate_keys(&keys));
    }

    #[test]
    fn test_validate_keys_no_keys() {
        let keys = DidKeys {
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            update_keys: None,
        };
        assert!(!Keys::default().validate_keys(&keys));
    }

    #[test]
    fn test_validate_keys_too_many_keys() {
        let key = dummy_key();
        let keys = DidKeys {
            authentication: vec![dummy_key(), key.clone()],
            assertion_method: vec![key.clone()],
            key_agreement: vec![key.clone()],
            capability_invocation: vec![key.clone()],
            capability_delegation: vec![key],
            update_keys: None,
        };
        assert!(!Keys::default().validate_keys(&keys));
    }
}
