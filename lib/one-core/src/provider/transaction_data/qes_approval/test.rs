use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde_json::json;
use similar_asserts::assert_eq;

use super::*;
use crate::provider::transaction_data::TransactionDataDisplayValue;

fn qes_approval_transaction_data() -> QesApprovalTransactionData {
    QesApprovalTransactionData::new(
        "QES_APPROVAL".into(),
        json!({
            "transactionDataDisplayParams": []
        }),
        one_crypto::initialize_crypto_provider(),
    )
    .unwrap()
}

fn encode(transaction_data: serde_json::Value) -> String {
    Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&transaction_data).unwrap())
        .unwrap()
}

// Example from https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/data-model-bindings.pdf
fn csc_example() -> serde_json::Value {
    json!({
        "type": "https://cloudsignatureconsortium.org/2025/qes-approval",
        "credential_ids": ["xyz123"],
        "numSignatures": 2,
        "signatureQualifier": "eu_eidas_qes",
        "documentInfos": [
            {
                "label": "Example Contract",
                "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                "hashType": "sodr",
                "access": { "type": "OTP", "oneTimePassword": "51623" },
                "href": "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
                "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
            },
            {
                "label": "Example Terms of Service",
                "hash": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
                "hashType": "sodr",
                "access": { "type": "public" },
                "href": "https://public.rp-cdn.example/terms-and-conditions.pdf",
                "checksum": "sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="
            },
            {
                "label": "Example Invoice",
                "hash": "nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ=",
                "hashType": "sodr",
                "access": { "type": "OTP", "oneTimePassword": "83920" },
                "href": "https://protected.rp.example/invoice-2025-07.pdf?token=jk47ns88sna9a",
                "checksum": "sha256-nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ="
            }
        ],
        "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
    })
}

#[test]
fn test_validate_transaction_data_csc_example() {
    let metadata = qes_approval_transaction_data()
        .validate_transaction_data(&encode(csc_example()))
        .unwrap();

    assert_eq!(
        metadata.credential_ids,
        vec![dcql::CredentialQueryId::from("xyz123")]
    );
}

#[tokio::test]
async fn test_process_transaction_data_returns_qes_approval_kb_jwt_claim() {
    use one_crypto::Hasher;
    use one_crypto::hasher::sha256::SHA256;

    let transaction_data = encode(csc_example());

    let processed = qes_approval_transaction_data()
        .process_transaction_data(&transaction_data, FormatType::SdJwtVc)
        .await
        .unwrap();

    // hashed over the encoded string as received
    let expected = SHA256.hash_base64(transaction_data.as_bytes()).unwrap();
    let ProcessedTransactionData::KbJwtClaims(fields) = processed else {
        panic!("expected KbJwtClaims, got {processed:?}");
    };
    assert_eq!(
        fields.get("org.cloudsignatureconsortium.dm.1.qesApproval"),
        Some(&serde_json::Value::from(expected))
    );
    assert_eq!(fields.len(), 1);
}

#[tokio::test]
async fn test_process_transaction_data_returns_qes_approval_device_signed_element() {
    use one_crypto::Hasher;
    use one_crypto::hasher::sha256::SHA256;

    let transaction_data = encode(csc_example());

    let processed = qes_approval_transaction_data()
        .process_transaction_data(&transaction_data, FormatType::Mdoc)
        .await
        .unwrap();

    // hashed over the decoded payload, as raw bytes
    let expected = SHA256
        .hash(&serde_json::to_vec(&csc_example()).unwrap())
        .unwrap();
    let ProcessedTransactionData::DeviceSignedElements(namespaces) = processed else {
        panic!("expected DeviceSignedElements, got {processed:?}");
    };
    assert_eq!(
        namespaces["org.cloudsignatureconsortium.dm.1"]["qesApproval"],
        ciborium::Value::Bytes(expected)
    );
}

#[tokio::test]
async fn test_process_transaction_data_rejects_unsupported_credential_format() {
    let result = qes_approval_transaction_data()
        .process_transaction_data(&encode(csc_example()), FormatType::Jwt)
        .await;

    assert!(matches!(
        result,
        Err(TransactionDataError::UnsupportedCredentialFormat(_))
    ));
}

#[test]
fn test_get_display_data_extracts_configured_paths() {
    let provider = QesApprovalTransactionData::new(
        "QES_APPROVAL".into(),
        json!({
            "transactionDataDisplayParams": [
                { "path": "$.documentInfos[*].label", "display": "documentLabels" },
                { "path": "$.signatureQualifier", "display": "signatureQualifier" },
                { "path": "$.doesNotExist", "display": "missing" }
            ]
        }),
        one_crypto::initialize_crypto_provider(),
    )
    .unwrap();

    let display_data = provider.get_display_data(&encode(csc_example())).unwrap();

    assert_eq!(
        display_data,
        vec![
            TransactionDataDisplayValue {
                display: "documentLabels".to_string(),
                values: vec![
                    json!("Example Contract"),
                    json!("Example Terms of Service"),
                    json!("Example Invoice"),
                ],
            },
            TransactionDataDisplayValue {
                display: "signatureQualifier".to_string(),
                values: vec![json!("eu_eidas_qes")],
            },
            TransactionDataDisplayValue {
                display: "missing".to_string(),
                values: vec![],
            },
        ]
    );
}

#[test]
fn test_validate_transaction_data_rejects_empty_credential_ids() {
    let mut transaction_data = csc_example();
    transaction_data["credential_ids"] = json!([]);

    let result =
        qes_approval_transaction_data().validate_transaction_data(&encode(transaction_data));
    assert!(matches!(
        result,
        Err(TransactionDataError::InvalidTransactionData(_))
    ));
}

#[test]
fn test_validate_transaction_data_rejects_missing_credential_id_and_qualifier() {
    let mut transaction_data = csc_example();
    transaction_data
        .as_object_mut()
        .unwrap()
        .remove("signatureQualifier");

    let result =
        qes_approval_transaction_data().validate_transaction_data(&encode(transaction_data));
    assert!(matches!(
        result,
        Err(TransactionDataError::InvalidTransactionData(_))
    ));
}

#[test]
fn test_validate_transaction_data_rejects_unsupported_hash_algorithm() {
    let mut transaction_data = csc_example();
    // sha-384, valid per CSC but not registered in the crypto provider
    transaction_data["hashAlgorithmOID"] = json!("2.16.840.1.101.3.4.2.2");

    let result =
        qes_approval_transaction_data().validate_transaction_data(&encode(transaction_data));
    assert!(matches!(
        result,
        Err(TransactionDataError::UnsupportedHashAlgorithm(_))
    ));
}

#[test]
fn test_validate_transaction_data_rejects_unknown_hash_algorithm_oid() {
    let mut transaction_data = csc_example();
    // sha-1
    transaction_data["hashAlgorithmOID"] = json!("1.3.14.3.2.26");

    let result =
        qes_approval_transaction_data().validate_transaction_data(&encode(transaction_data));
    assert!(matches!(result, Err(TransactionDataError::Parsing(_))));
}

#[test]
fn test_validate_transaction_data_rejects_invalid_base64url() {
    let result = qes_approval_transaction_data().validate_transaction_data("not/valid+base64url");
    assert!(matches!(result, Err(TransactionDataError::Encoding(_))));
}
