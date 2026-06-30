use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::model::GeneratedKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared_types::DidValue;

use crate::fixtures::jwt::signed_jwt;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VP {
    pub vp: VPContent,
    pub nonce: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VPContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<String>,
}

pub(crate) async fn w3c_jwt_vc(
    key: &GeneratedKey,
    alg: &str,
    iss: DidValue,
    sub: DidValue,
    credential_subject: serde_json::Value,
) -> String {
    let vc = json!({
        "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "credentialSubject": credential_subject
      }
    });
    signed_jwt(
        key,
        alg,
        None,
        Some(iss.to_string()),
        Some(sub.to_string()),
        vc,
        None,
    )
    .await
}

pub(crate) async fn w3c_jwt_enveloped_presentation(
    key: &GeneratedKey,
    alg: &str,
    credential_presentations: Vec<String>,
    iss: DidValue,
    sub: DidValue,
    nonce: Option<String>,
) -> String {
    let vp = VP {
        vp: VPContent {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            r#type: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: credential_presentations,
        },
        nonce,
    };
    signed_jwt(
        key,
        alg,
        None,
        Some(iss.to_string()),
        Some(sub.to_string()),
        vp,
        None,
    )
    .await
}

pub(crate) async fn dummy_presentations() -> (String, String) {
    let alg = "ES256";
    let holder_key_pair1 = Ecdsa.generate_key().unwrap();
    let multibase1 = holder_key_pair1.key.public_key_as_multibase().unwrap();
    let holder_did1 = DidValue::from_did_url(format!("did:key:{}", multibase1).as_str()).unwrap();

    let issuer_key_pair = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key_pair.key.public_key_as_multibase().unwrap();
    let issuer_did = DidValue::from_did_url(format!("did:key:{}", multibase).as_str()).unwrap();

    let pet_cred_subj = json!({
      "pet1": "PET1",
      "pet2": "PET2"
    });
    let name_cred_subj = json!({
      "name1": "NAME1",
      "name2": "NAME2"
    });
    let cat_cred_subj = json!({
      "cat1": "CAT1"
    });

    let token1 = w3c_jwt_vc(
        &issuer_key_pair,
        alg,
        issuer_did.clone(),
        holder_did1.clone(),
        pet_cred_subj,
    )
    .await;
    let token2 = w3c_jwt_vc(
        &issuer_key_pair,
        alg,
        issuer_did.clone(),
        holder_did1.clone(),
        name_cred_subj,
    )
    .await;
    let pres1 = w3c_jwt_enveloped_presentation(
        &holder_key_pair1,
        alg,
        vec![token1, token2],
        holder_did1.clone(),
        holder_did1.clone(),
        Some("nonce123".to_string()),
    )
    .await;

    let holder_key_pair2 = Ecdsa.generate_key().unwrap();
    let multibase2 = holder_key_pair2.key.public_key_as_multibase().unwrap();
    let holder_did2 = DidValue::from_did_url(format!("did:key:{}", multibase2).as_str()).unwrap();

    let token3 = w3c_jwt_vc(
        &issuer_key_pair,
        alg,
        issuer_did,
        holder_did2.clone(),
        cat_cred_subj,
    )
    .await;

    let pres2 = w3c_jwt_enveloped_presentation(
        &holder_key_pair2,
        alg,
        vec![token3],
        holder_did2.clone(),
        holder_did2,
        Some("nonce123".to_string()),
    )
    .await;
    (pres1, pres2)
}

async fn single_credential_presentation(credential_subject: serde_json::Value) -> String {
    let alg = "ES256";
    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let multibase = holder_key_pair.key.public_key_as_multibase().unwrap();
    let holder_did = DidValue::from_did_url(format!("did:key:{multibase}").as_str()).unwrap();

    let issuer_key_pair = Ecdsa.generate_key().unwrap();
    let issuer_multibase = issuer_key_pair.key.public_key_as_multibase().unwrap();
    let issuer_did =
        DidValue::from_did_url(format!("did:key:{issuer_multibase}").as_str()).unwrap();

    let token = w3c_jwt_vc(
        &issuer_key_pair,
        alg,
        issuer_did,
        holder_did.clone(),
        credential_subject,
    )
    .await;

    w3c_jwt_enveloped_presentation(
        &holder_key_pair,
        alg,
        vec![token],
        holder_did.clone(),
        holder_did,
        Some("nonce123".to_string()),
    )
    .await
}

/// Returns three separate single-credential presentations (name, pet, cat), one credential each,
/// as required by the DCQL flow where each credential query maps to its own presentation.
pub(crate) async fn dummy_single_credential_presentations() -> (String, String, String) {
    let name_presentation = single_credential_presentation(json!({
      "name1": "NAME1",
      "name2": "NAME2"
    }))
    .await;
    let pet_presentation = single_credential_presentation(json!({
      "pet1": "PET1",
      "pet2": "PET2"
    }))
    .await;
    let cat_presentation = single_credential_presentation(json!({
      "cat1": "CAT1"
    }))
    .await;
    (name_presentation, pet_presentation, cat_presentation)
}
