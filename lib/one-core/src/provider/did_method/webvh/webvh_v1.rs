use std::ops::Add;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{OneOrMany, serde_as};
use shared_types::DidValue;
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;

use super::Params;
use super::common::{canonicalized_hash, multihash_b58_encode};
use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::error::DidMethodError::{Deactivated, ResolutionError};
use crate::provider::did_method::model::DidDocument;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::eddsa::Eddsa;
use crate::provider::key_algorithm::key::KeyHandle;

const METHOD_VERSION: &str = "did:webvh:1.0";
const SCID_PLACEHOLDER: &str = "{SCID}";

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DidLogEntry {
    version_id: String,
    version_time: String,
    parameters: DidLogParameters,
    state: Value,
    #[serde(default)]
    #[serde_as(as = "OneOrMany<_>")]
    proof: Vec<VcdmProof>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DidLogParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_key_hashes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    portable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deactivated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    watchers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedDidLogEntry<'a> {
    version_id: &'a str,
    version_time: &'a str,
    parameters: &'a DidLogParameters,
    state: &'a Value,
}

pub(super) async fn resolve_log(
    did: &DidValue,
    expected_scid: &str,
    body: &[u8],
    did_method_provider: &dyn DidMethodProvider,
    params: &Params,
) -> Result<DidDocument, DidMethodError> {
    let body = std::str::from_utf8(body)
        .map_err(|err| ResolutionError(format!("Invalid did:webvh log encoding: {err}")))?;
    let entries = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<DidLogEntry>(line)
                .map_err(|err| ResolutionError(format!("Invalid did:webvh v1 log entry: {err}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if entries.is_empty() {
        return Err(ResolutionError("Did log is empty".to_string()));
    }
    if let Some(limit) = params.max_did_log_entry_check
        && entries.len() > limit as usize
    {
        return Err(ResolutionError(format!(
            "Failed to verify did log: log has {} entries which is more than the max allowed length ({limit})",
            entries.len()
        )));
    }

    verify_log(&entries, did, expected_scid, did_method_provider, params).await?;

    let mut state = entries
        .last()
        .ok_or_else(|| ResolutionError("Did log is empty".to_string()))?
        .state
        .clone();
    normalize_multikey_verification_methods(&mut state)?;
    let document = DidDocumentDTO::deserialize(state)
        .map_err(|err| ResolutionError(format!("Invalid did:webvh DID document: {err}")))?;
    Ok(document.into())
}

async fn verify_log(
    entries: &[DidLogEntry],
    requested_did: &DidValue,
    expected_scid: &str,
    did_method_provider: &dyn DidMethodProvider,
    params: &Params,
) -> Result<(), DidMethodError> {
    let first = entries
        .first()
        .ok_or_else(|| ResolutionError("Did log is empty".to_string()))?;
    if first.parameters.method.as_deref() != Some(METHOD_VERSION) {
        return Err(ResolutionError(format!(
            "Unsupported did:webvh method version: {:?}",
            first.parameters.method
        )));
    }
    if first.parameters.scid.as_deref() != Some(expected_scid) {
        return Err(ResolutionError(
            "SCID in DID does not match SCID in log".to_string(),
        ));
    }
    if first.parameters.portable.unwrap_or_default() {
        return Err(ResolutionError(
            "Portable did:webvh histories are not supported".to_string(),
        ));
    }
    ensure_no_witness_requirement(first.parameters.witness.as_ref())?;

    let mut active_update_keys = first
        .parameters
        .update_keys
        .clone()
        .filter(|keys| !keys.is_empty())
        .ok_or_else(|| ResolutionError("Missing initial updateKeys".to_string()))?;
    let mut active_next_key_hashes = first.parameters.next_key_hashes.clone().unwrap_or_default();
    let mut previous_version_id: Option<&str> = None;
    let mut previous_time = None;
    let now = crate::clock::now_utc();

    for (index, entry) in entries.iter().enumerate() {
        let expected_version = index + 1;
        let entry_hash = parse_version_id(&entry.version_id, expected_version)?;
        let version_time = parse_version_time(&entry.version_time)?;

        if version_time > now.add(params.leeway) {
            return Err(ResolutionError(format!(
                "Invalid log entry {}: version time is in the future",
                entry.version_id
            )));
        }
        if let Some(previous_time) = previous_time
            && version_time <= previous_time
        {
            return Err(ResolutionError(format!(
                "Invalid log entry {}: version time must be greater than the previous entry time",
                entry.version_id
            )));
        }
        previous_time = Some(version_time);

        let state_id = entry
            .state
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| ResolutionError("DID document id is missing".to_string()))?;
        if state_id != requested_did.as_str() {
            return Err(ResolutionError(format!(
                "Did log state id '{state_id}' does not match requested DID '{requested_did}'"
            )));
        }

        if entry.parameters.deactivated.unwrap_or_default() {
            return Err(Deactivated);
        }
        ensure_no_witness_requirement(entry.parameters.witness.as_ref())?;

        if index == 0 {
            verify_scid(first, expected_scid)?;
        } else {
            if let Some(method) = entry.parameters.method.as_deref()
                && method != METHOD_VERSION
            {
                return Err(ResolutionError(format!(
                    "Unsupported or downgraded did:webvh method version: {method}"
                )));
            }
            if entry.parameters.scid.is_some() {
                return Err(ResolutionError(
                    "SCID parameter is only allowed in the first log entry".to_string(),
                ));
            }
            if entry.parameters.portable.unwrap_or_default() {
                return Err(ResolutionError(
                    "portable can only be enabled in the first log entry".to_string(),
                ));
            }
        }

        let hash_input_version = previous_version_id.unwrap_or(expected_scid);
        let derived_entry_hash = derive_entry_hash(entry, hash_input_version)?;
        if derived_entry_hash != entry_hash {
            return Err(ResolutionError(format!(
                "Hash chain broken at '{}'",
                entry.version_id
            )));
        }

        let prerotation = !active_next_key_hashes.is_empty();
        let proof_update_keys = if index > 0 && prerotation {
            entry
                .parameters
                .update_keys
                .as_ref()
                .filter(|keys| !keys.is_empty())
                .ok_or_else(|| {
                    ResolutionError(format!(
                        "Entry {} is missing updateKeys required by prerotation",
                        entry.version_id
                    ))
                })?
        } else {
            &active_update_keys
        };
        verify_proofs(entry, proof_update_keys, did_method_provider).await?;

        if index > 0 && prerotation {
            verify_prerotated_keys(proof_update_keys, &active_next_key_hashes)?;
        }
        if let Some(update_keys) = entry.parameters.update_keys.as_ref() {
            active_update_keys = update_keys.clone();
        }
        if let Some(next_key_hashes) = entry.parameters.next_key_hashes.as_ref() {
            active_next_key_hashes = next_key_hashes.clone();
        }
        previous_version_id = Some(&entry.version_id);
    }

    Ok(())
}

fn parse_version_id(version_id: &str, expected_version: usize) -> Result<&str, DidMethodError> {
    let (version, entry_hash) = version_id
        .split_once('-')
        .ok_or_else(|| ResolutionError(format!("Invalid versionId '{version_id}'")))?;
    if entry_hash.contains('-') || entry_hash.is_empty() {
        return Err(ResolutionError(format!("Invalid versionId '{version_id}'")));
    }
    let version = version
        .parse::<usize>()
        .map_err(|_| ResolutionError(format!("Invalid versionId '{version_id}'")))?;
    if version != expected_version {
        return Err(ResolutionError(format!(
            "Unexpected versionId '{version_id}', expected version {expected_version}"
        )));
    }
    Ok(entry_hash)
}

fn verify_scid(entry: &DidLogEntry, expected_scid: &str) -> Result<(), DidMethodError> {
    let mut value = unsigned_entry_value(entry, SCID_PLACEHOLDER)?;
    replace_string_value(&mut value, expected_scid, SCID_PLACEHOLDER);
    let derived_scid = hash_value(value)?;
    if derived_scid != expected_scid {
        return Err(ResolutionError(format!(
            "Invalid SCID: expected {expected_scid}, got {derived_scid}"
        )));
    }
    Ok(())
}

fn derive_entry_hash(
    entry: &DidLogEntry,
    hash_input_version: &str,
) -> Result<String, DidMethodError> {
    hash_value(unsigned_entry_value(entry, hash_input_version)?)
}

fn unsigned_entry_value(entry: &DidLogEntry, version_id: &str) -> Result<Value, DidMethodError> {
    serde_json::to_value(UnsignedDidLogEntry {
        version_id,
        version_time: &entry.version_time,
        parameters: &entry.parameters,
        state: &entry.state,
    })
    .map_err(|err| ResolutionError(format!("Failed to serialize DID log entry: {err}")))
}

fn hash_value(value: Value) -> Result<String, DidMethodError> {
    let value = json_syntax::Value::from_serde_json(value);
    let hash = canonicalized_hash(value)?;
    multihash_b58_encode(&hash)
        .map_err(|err| ResolutionError(format!("Failed to encode DID log hash: {err}")))
}

fn replace_string_value(value: &mut Value, search: &str, replacement: &str) {
    match value {
        Value::String(text) => {
            *text = text.replace(search, replacement);
        }
        Value::Array(values) => {
            for value in values {
                replace_string_value(value, search, replacement);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_string_value(value, search, replacement);
            }
        }
        _ => {}
    }
}

async fn verify_proofs(
    entry: &DidLogEntry,
    update_keys: &[String],
    did_method_provider: &dyn DidMethodProvider,
) -> Result<(), DidMethodError> {
    if entry.proof.is_empty() {
        return Err(ResolutionError(format!(
            "Missing proof in DID log entry {}",
            entry.version_id
        )));
    }

    for proof in &entry.proof {
        if proof.r#type != "DataIntegrityProof" {
            return Err(ResolutionError(format!(
                "Unsupported proof type '{}'",
                proof.r#type
            )));
        }
        if proof.cryptosuite != "eddsa-jcs-2022" {
            return Err(ResolutionError(format!(
                "Unsupported cryptosuite '{}'",
                proof.cryptosuite
            )));
        }
        if proof.proof_purpose != "assertionMethod" {
            return Err(ResolutionError(format!(
                "Invalid proof purpose '{}'",
                proof.proof_purpose
            )));
        }
        if proof.created != Some(parse_version_time(&entry.version_time)?) {
            return Err(ResolutionError(format!(
                "Proof created time does not match version time for entry {}",
                entry.version_id
            )));
        }

        let (key_multibase, key_handle) =
            verification_key(proof, update_keys, did_method_provider).await?;
        if !update_keys.contains(&key_multibase) {
            return Err(ResolutionError(format!(
                "Proof verification method is not an authorized update key for entry {}",
                entry.version_id
            )));
        }

        let mut proof_without_value = proof.clone();
        let proof_value = proof_without_value.proof_value.take().ok_or_else(|| {
            ResolutionError(format!(
                "Missing proofValue for DID log entry {}",
                entry.version_id
            ))
        })?;
        let signature = proof_value
            .strip_prefix('z')
            .ok_or_else(|| ResolutionError("proofValue must use base58btc multibase".to_string()))
            .and_then(|encoded| {
                bs58::decode(encoded)
                    .into_vec()
                    .map_err(|err| ResolutionError(format!("Failed to decode proofValue: {err}")))
            })?;

        let proof_value = json_syntax::to_value(proof_without_value)
            .map_err(|err| ResolutionError(format!("Failed to serialize proof: {err}")))?;
        let mut message = canonicalized_hash(proof_value)?;
        let unsigned_entry = unsigned_entry_value(entry, &entry.version_id)?;
        let mut document_hash =
            canonicalized_hash(json_syntax::Value::from_serde_json(unsigned_entry))?;
        message.append(&mut document_hash);

        key_handle.verify(&message, &signature).map_err(|err| {
            ResolutionError(format!(
                "Failed to verify integrity proof for entry {}: {err}",
                entry.version_id
            ))
        })?;
    }

    Ok(())
}

async fn verification_key(
    proof: &VcdmProof,
    update_keys: &[String],
    did_method_provider: &dyn DidMethodProvider,
) -> Result<(String, KeyHandle), DidMethodError> {
    let verification_method = proof
        .verification_method
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            ResolutionError("DID log proof verificationMethod must use did:key".to_string())
        })?;
    let (key_multibase, fragment) = verification_method
        .split_once('#')
        .map(|(key, fragment)| (key, Some(fragment)))
        .unwrap_or((verification_method, None));
    if key_multibase.is_empty() || fragment.is_some_and(|fragment| fragment != key_multibase) {
        return Err(ResolutionError(
            "Invalid did:key proof verificationMethod".to_string(),
        ));
    }
    if !update_keys.iter().any(|key| key == key_multibase) {
        return Err(ResolutionError(
            "DID log proof key is not authorized by updateKeys".to_string(),
        ));
    }

    let did = format!("did:key:{key_multibase}")
        .parse::<DidValue>()
        .map_err(|err| ResolutionError(format!("Invalid did:key proof identifier: {err}")))?;
    let document = did_method_provider
        .resolve(&did)
        .await
        .map_err(|err| ResolutionError(format!("Failed to resolve DID log proof key: {err}")))?;
    let verification_method = document.verification_method.first().ok_or_else(|| {
        ResolutionError("Resolved did:key document has no verification method".to_string())
    })?;
    let key_handle = Eddsa
        .parse_jwk(&verification_method.public_key_jwk)
        .map_err(|err| ResolutionError(format!("Failed to parse Ed25519 public key: {err}")))?;
    let resolved_multibase = key_handle
        .public_key_as_multibase()
        .map_err(|err| ResolutionError(format!("Failed to encode Ed25519 public key: {err}")))?;
    if resolved_multibase != key_multibase {
        return Err(ResolutionError(
            "Resolved did:key does not match proof verificationMethod".to_string(),
        ));
    }

    Ok((key_multibase.to_string(), key_handle))
}

fn verify_prerotated_keys(
    update_keys: &[String],
    previous_next_key_hashes: &[String],
) -> Result<(), DidMethodError> {
    for update_key in update_keys {
        let hash = SHA256.hash(update_key.as_bytes()).map_err(|err| {
            ResolutionError(format!("Failed to hash prerotated update key: {err}"))
        })?;
        let hash = multihash_b58_encode(&hash)
            .map_err(|err| ResolutionError(format!("Failed to encode update key hash: {err}")))?;
        if !previous_next_key_hashes.contains(&hash) {
            return Err(ResolutionError(format!(
                "Update key is not committed by previous nextKeyHashes: {hash}"
            )));
        }
    }
    Ok(())
}

fn ensure_no_witness_requirement(witness: Option<&Value>) -> Result<(), DidMethodError> {
    let witness_is_empty = match witness {
        None | Some(Value::Null) => true,
        Some(Value::Object(object)) => object.is_empty(),
        _ => false,
    };
    if !witness_is_empty {
        return Err(ResolutionError(
            "Witness-constrained did:webvh histories are not supported".to_string(),
        ));
    }
    Ok(())
}

fn normalize_multikey_verification_methods(state: &mut Value) -> Result<(), DidMethodError> {
    let Some(methods) = state
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
    else {
        return Ok(());
    };

    for method in methods {
        let Some(method) = method.as_object_mut() else {
            return Err(ResolutionError(
                "DID verificationMethod must be an object".to_string(),
            ));
        };
        if method.contains_key("publicKeyJwk") {
            continue;
        }
        let multibase = method
            .get("publicKeyMultibase")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ResolutionError(
                    "DID verificationMethod must contain publicKeyJwk or publicKeyMultibase"
                        .to_string(),
                )
            })?;
        let encoded = multibase.strip_prefix('z').ok_or_else(|| {
            ResolutionError("publicKeyMultibase must use base58btc multibase".to_string())
        })?;
        let decoded = bs58::decode(encoded)
            .into_vec()
            .map_err(|err| ResolutionError(format!("Invalid verification key multibase: {err}")))?;
        let (codec, key) = decoded
            .split_at_checked(2)
            .ok_or_else(|| ResolutionError("Invalid verification key multicodec".to_string()))?;
        if key.len() != 32 {
            return Err(ResolutionError(
                "Ed25519/X25519 verification keys must be 32 bytes".to_string(),
            ));
        }
        let crv = match codec {
            [0xed, 0x01] => "Ed25519",
            [0xec, 0x01] => "X25519",
            _ => {
                return Err(ResolutionError(
                    "Unsupported publicKeyMultibase algorithm".to_string(),
                ));
            }
        };
        let public_key_jwk = PublicJwk::Okp(PublicJwkEc {
            alg: None,
            r#use: None,
            kid: None,
            crv: crv.to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(key).map_err(|err| {
                ResolutionError(format!("Failed to encode verification key: {err}"))
            })?,
            y: None,
        });
        method.insert(
            "publicKeyJwk".to_string(),
            serde_json::to_value(public_key_jwk).map_err(|err| {
                ResolutionError(format!("Failed to serialize verification key: {err}"))
            })?,
        );
    }
    Ok(())
}

fn parse_version_time(value: &str) -> Result<OffsetDateTime, DidMethodError> {
    if !value.ends_with('Z') {
        return Err(ResolutionError(
            "did:webvh versionTime must use UTC Z notation".to_string(),
        ));
    }
    OffsetDateTime::parse(value, &Iso8601::DEFAULT)
        .map_err(|err| ResolutionError(format!("Invalid did:webvh versionTime: {err}")))
}
