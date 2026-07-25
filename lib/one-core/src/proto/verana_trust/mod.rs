use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use time::Duration;
use url::Url;

use crate::model::verana_trust::{
    VeranaAuthorizationEvidence, VeranaQ1Evidence, VeranaTrustClaim, VeranaTrustCredential,
    VeranaTrustFullDetails,
};
pub(crate) use crate::model::verana_trust::{
    VeranaTrustRole, VeranaTrustSummary, VeranaTrustVerdict,
};
use crate::proto::http_client::HttpClient;

pub(crate) struct VeranaTrustResolver {
    resolver_url: Url,
    timeout: Duration,
    http_client: Arc<dyn HttpClient>,
}

#[derive(Debug, Error)]
pub(crate) enum VeranaTrustResolverError {
    #[error("invalid Verana resolver URL")]
    InvalidResolverUrl,
    #[error("Verana full details unavailable")]
    Unavailable,
    #[error("Verana full details do not match the validated summary")]
    Mismatch,
    #[error("Verana full details are malformed")]
    Malformed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Q1Response {
    did: Option<String>,
    trust_status: Option<String>,
    production: Option<bool>,
    evaluated_at: Option<String>,
    evaluated_at_block: Option<Value>,
    expires_at: Option<String>,
}

impl From<Q1Response> for VeranaQ1Evidence {
    fn from(value: Q1Response) -> Self {
        Self {
            response_did: value.did,
            trust_status: value.trust_status,
            production: value.production,
            evaluated_at: value.evaluated_at,
            evaluated_at_block: value.evaluated_at_block,
            expires_at: value.expires_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationResponse {
    did: Option<String>,
    vtjsc_id: Option<String>,
    authorized: Option<bool>,
    evaluated_at: Option<String>,
    permission: Option<Value>,
    fees: Option<Value>,
    permission_chain: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullResponse {
    did: Option<String>,
    trust_status: Option<String>,
    production: Option<bool>,
    evaluated_at: Option<String>,
    evaluated_at_block: Option<Value>,
    expires_at: Option<String>,
    credentials: Option<Vec<FullCredentialResponse>>,
    failed_credentials: Option<Vec<Value>>,
    dereference_errors: Option<Vec<Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullCredentialResponse {
    id: Option<String>,
    #[serde(rename = "type")]
    credential_type: Option<String>,
    format: Option<String>,
    ecs_type: Option<String>,
    issued_by: Option<String>,
    presented_by: Option<String>,
    claims: Option<BTreeMap<String, Value>>,
    permission_chain: Option<Vec<Value>>,
    result: Option<String>,
}

impl VeranaTrustResolver {
    pub(crate) fn new(
        resolver_url: String,
        timeout: Duration,
        http_client: Arc<dyn HttpClient>,
    ) -> Result<Self, VeranaTrustResolverError> {
        let resolver_url =
            Url::parse(&resolver_url).map_err(|_| VeranaTrustResolverError::InvalidResolverUrl)?;
        if resolver_url.scheme() != "https"
            || resolver_url.host_str().is_none()
            || !resolver_url.username().is_empty()
            || resolver_url.password().is_some()
            || resolver_url.query().is_some()
            || resolver_url.fragment().is_some()
        {
            return Err(VeranaTrustResolverError::InvalidResolverUrl);
        }
        Ok(Self {
            resolver_url,
            timeout,
            http_client,
        })
    }

    pub(crate) async fn resolve_summary(
        &self,
        role: VeranaTrustRole,
        did: &str,
        schemas: Vec<String>,
    ) -> VeranaTrustSummary {
        let has_invalid_schema = schemas
            .iter()
            .any(|schema| schema.trim().is_empty() || schema != schema.trim());
        let schemas = schemas
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let mut summary = VeranaTrustSummary {
            resolver_url: self
                .resolver_url
                .to_string()
                .trim_end_matches('/')
                .to_string(),
            role,
            verdict: VeranaTrustVerdict::Unavailable,
            did: did.to_string(),
            schemas,
            q1: None,
            authorizations: vec![],
            failure: None,
        };

        let q1 = match self.get_q1(did, "summary").await {
            Ok(q1) => q1,
            Err(failure) => {
                summary.failure = Some(failure);
                return summary;
            }
        };
        summary.q1 = Some(q1);

        let q1 = summary.q1.as_ref().expect("Q1 evidence set above");
        if q1.response_did.as_deref() != Some(did) {
            summary.verdict = VeranaTrustVerdict::Mismatch;
            return summary;
        }
        match (q1.trust_status.as_deref(), q1.production) {
            (Some("TRUSTED"), Some(true)) => {}
            (Some("TRUSTED"), Some(false)) => {
                summary.verdict = VeranaTrustVerdict::NonProduction;
                return summary;
            }
            (Some("UNTRUSTED"), Some(_)) => {
                summary.verdict = VeranaTrustVerdict::Untrusted;
                return summary;
            }
            _ => {
                summary.verdict = VeranaTrustVerdict::Partial;
                return summary;
            }
        }

        if has_invalid_schema || summary.schemas.is_empty() {
            summary.verdict = VeranaTrustVerdict::UnknownSchema;
            return summary;
        }

        let mut authorization_unavailable = false;
        let mut authorization_mismatch = false;
        let mut authorization_partial = false;
        let mut unauthorized = false;
        for schema in &summary.schemas {
            let response = match self.get_authorization(role, did, schema).await {
                Ok(response) => response,
                Err(failure) => {
                    summary.failure.get_or_insert(failure);
                    authorization_unavailable = true;
                    summary.authorizations.push(VeranaAuthorizationEvidence {
                        schema: schema.clone(),
                        response_did: None,
                        response_schema: None,
                        authorized: None,
                        evaluated_at: None,
                        evaluated_at_block: None,
                        permission: None,
                        fees: None,
                        permission_chain: None,
                    });
                    continue;
                }
            };
            let evidence = VeranaAuthorizationEvidence {
                schema: schema.clone(),
                response_did: response.0.did,
                response_schema: response.0.vtjsc_id,
                authorized: response.0.authorized,
                evaluated_at: response.0.evaluated_at,
                evaluated_at_block: response.1,
                permission: response.0.permission,
                fees: response.0.fees,
                permission_chain: response.0.permission_chain,
            };
            let exact_match = evidence.response_did.as_deref() == Some(did)
                && evidence.response_schema.as_deref() == Some(schema.as_str());
            let complete = evidence.authorized.is_some();
            unauthorized |= evidence.authorized == Some(false);
            summary.authorizations.push(evidence);
            if !exact_match {
                authorization_mismatch = true;
            }
            if !complete {
                authorization_partial = true;
            }
        }

        summary.verdict = if authorization_mismatch {
            VeranaTrustVerdict::Mismatch
        } else if authorization_unavailable {
            VeranaTrustVerdict::Unavailable
        } else if authorization_partial {
            VeranaTrustVerdict::Partial
        } else if unauthorized {
            VeranaTrustVerdict::Unauthorized
        } else {
            VeranaTrustVerdict::TrustedAuthorized
        };
        summary
    }

    pub(crate) fn unsupported_summary(
        &self,
        role: VeranaTrustRole,
        did: Option<&str>,
        schemas: Vec<String>,
        reason: &str,
    ) -> VeranaTrustSummary {
        VeranaTrustSummary {
            resolver_url: self
                .resolver_url
                .to_string()
                .trim_end_matches('/')
                .to_string(),
            role,
            verdict: if schemas.iter().any(|schema| schema.trim().is_empty()) || schemas.is_empty()
            {
                VeranaTrustVerdict::UnknownSchema
            } else {
                VeranaTrustVerdict::Unavailable
            },
            did: did.unwrap_or_default().to_string(),
            schemas,
            q1: None,
            authorizations: vec![],
            failure: Some(reason.to_string()),
        }
    }

    pub(crate) async fn resolve_full(
        &self,
        summary: &VeranaTrustSummary,
    ) -> Result<VeranaTrustFullDetails, VeranaTrustResolverError> {
        let url = self.q1_url(&summary.did, "full");
        let response = self
            .http_client
            .get(url.as_str())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|_| VeranaTrustResolverError::Unavailable)?
            .error_for_status()
            .map_err(|_| VeranaTrustResolverError::Unavailable)?
            .json::<FullResponse>()
            .map_err(|_| VeranaTrustResolverError::Malformed)?;

        let did = response.did.ok_or(VeranaTrustResolverError::Malformed)?;
        let trust_status = response
            .trust_status
            .ok_or(VeranaTrustResolverError::Malformed)?;
        let production = response
            .production
            .ok_or(VeranaTrustResolverError::Malformed)?;
        let q1 = summary
            .q1
            .as_ref()
            .ok_or(VeranaTrustResolverError::Mismatch)?;
        if did != summary.did
            || q1.trust_status.as_deref() != Some(trust_status.as_str())
            || q1.production != Some(production)
        {
            return Err(VeranaTrustResolverError::Mismatch);
        }

        let credentials = response
            .credentials
            .ok_or(VeranaTrustResolverError::Malformed)?
            .into_iter()
            .map(map_full_credential)
            .collect();
        Ok(VeranaTrustFullDetails {
            resolver_url: summary.resolver_url.clone(),
            did,
            trust_status,
            production,
            evaluated_at: response.evaluated_at,
            evaluated_at_block: response.evaluated_at_block,
            expires_at: response.expires_at,
            credentials,
            failed_credentials: response.failed_credentials.unwrap_or_default(),
            dereference_errors: response.dereference_errors.unwrap_or_default(),
        })
    }

    async fn get_q1(&self, did: &str, detail: &str) -> Result<VeranaQ1Evidence, String> {
        let url = self.q1_url(did, detail);
        self.http_client
            .get(url.as_str())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|_| "Q1_NETWORK".to_string())?
            .error_for_status()
            .map_err(|_| "Q1_HTTP".to_string())?
            .json::<Q1Response>()
            .map(Into::into)
            .map_err(|_| "Q1_MALFORMED".to_string())
    }

    async fn get_authorization(
        &self,
        role: VeranaTrustRole,
        did: &str,
        schema: &str,
    ) -> Result<(AuthorizationResponse, Option<String>), String> {
        let path = match role {
            VeranaTrustRole::Issuer => "/v1/trust/issuer-authorization",
            VeranaTrustRole::Verifier => "/v1/trust/verifier-authorization",
        };
        let mut url = self.resolver_url.clone();
        url.set_path(path);
        url.set_query(None);
        url.query_pairs_mut()
            .append_pair("did", did)
            .append_pair("vtjscId", schema);
        let response = self
            .http_client
            .get(url.as_str())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|_| "AUTHORIZATION_NETWORK".to_string())?
            .error_for_status()
            .map_err(|_| "AUTHORIZATION_HTTP".to_string())?;
        let block = response.header_get("X-Evaluated-At-Block").cloned();
        response
            .json::<AuthorizationResponse>()
            .map(|body| (body, block))
            .map_err(|_| "AUTHORIZATION_MALFORMED".to_string())
    }

    fn q1_url(&self, did: &str, detail: &str) -> Url {
        let mut url = self.resolver_url.clone();
        url.set_path("/v1/trust/resolve");
        url.set_query(None);
        url.query_pairs_mut()
            .append_pair("did", did)
            .append_pair("detail", detail);
        url
    }
}

fn map_full_credential(value: FullCredentialResponse) -> VeranaTrustCredential {
    let claims = value
        .claims
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| VeranaTrustClaim {
            name,
            value_type: json_value_type(&value).to_string(),
            value: match value {
                Value::String(value) => value,
                value => value.to_string(),
            },
        })
        .collect();
    VeranaTrustCredential {
        id: value.id,
        credential_type: value.credential_type,
        format: value.format,
        ecs_type: value.ecs_type,
        issued_by: value.issued_by,
        presented_by: value.presented_by,
        claims,
        permission_chain: value.permission_chain.unwrap_or_default(),
        result: value.result,
    }
}

fn json_value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod test;
