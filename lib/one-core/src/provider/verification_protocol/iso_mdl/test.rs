use std::collections::HashSet;
use std::sync::Arc;

use maplit::{hashmap, hashset};
use secrecy::SecretSlice;
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::IsoMdl;
use crate::config::core_config::VerificationEngagement;
use crate::mapper::credential_schema_claim::backfill_default_translations;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialRole, CredentialStateEnum, CredentialType, GetCredentialList,
};
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::proto::bluetooth_low_energy::ble_resource::{BleWaiter, OnConflict};
use crate::proto::bluetooth_low_energy::low_level::ble_central::MockBleCentral;
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::MockBlePeripheral;
use crate::proto::trust_information::MockTrustInformationProvider;
use crate::proto::wrp_validator::MockWRPValidator;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::verification_protocol::VerificationProtocol;
use crate::provider::verification_protocol::dto::{
    ApplicableCredentialOrFailureHintEnum, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::ble_holder::{
    MdocBleHolderInteractionData, MdocBleHolderInteractionSessionData,
};
use crate::provider::verification_protocol::iso_mdl::common::{
    DeviceRequest, DocRequest, ItemsRequest, SkDevice, SkReader, to_cbor,
};
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::service::test_utilities::{dummy_organisation, generic_config};

#[tokio::test]
async fn test_presentation_reject_ok() {
    let core_config = generic_config().core;
    let mut ble_peripheral = MockBlePeripheral::new();
    ble_peripheral
        .expect_notify_characteristic_data()
        .times(1)
        .returning(move |_, _, _, _| Ok(()));

    ble_peripheral
        .expect_is_advertising()
        .times(1)
        .returning(move || Ok(false));

    ble_peripheral
        .expect_stop_server()
        .times(1)
        .returning(move || Ok(()));

    let mut ble_central = MockBleCentral::new();
    ble_central
        .expect_is_scanning()
        .times(1)
        .returning(move || Ok(false));

    let ble_waiter = BleWaiter::new(Arc::new(ble_central), Arc::new(ble_peripheral));
    let (continuation_task_id, _) = ble_waiter
        .schedule(
            Uuid::new_v4(),
            |_, _, _| async { Ok(()) as Result<(), VerificationProtocolError> },
            |_, _| async {},
            OnConflict::DoNothing,
            true,
        )
        .await
        .value_or(anyhow::anyhow!("test"))
        .await
        .unwrap();

    let provider = IsoMdl::new(
        "ISO_MDL".to_string(),
        Arc::new(core_config),
        Arc::new(MockCredentialRepository::new()),
        Arc::new(MockPresentationFormatterProvider::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockCredentialSchemaRepository::new()),
        Arc::new(MockCredentialFormatterProvider::new()),
        Arc::new(MockTrustInformationProvider::new()),
        Arc::new(MockWRPValidator::new()),
        Some(ble_waiter),
        None,
    );

    let schema_id = "org.iso.18013.5.1".to_string();
    let organisation_id = Uuid::new_v4().into();
    let device_request_bytes = to_cbor(&DeviceRequest {
        version: "1.0".to_string(),
        doc_requests: vec![DocRequest {
            items_request: EmbeddedCbor::new(ItemsRequest {
                doc_type: schema_id.clone(),
                name_spaces: hashmap! {
                    "org.iso.18013.5.1.mDL".to_string() => hashmap! {
                        "name".to_string() => true,
                        "age".to_string() => true,
                        "country".to_string() => true,
                        "info".to_string() => true,
                    }
                },
            })
            .unwrap(),
        }],
    })
    .unwrap();

    let interaction_data = serde_json::to_vec(&MdocBleHolderInteractionData {
        service_uuid: Uuid::new_v4(),
        continuation_task_id,
        organisation_id,
        engagement: HashSet::from([VerificationEngagement::QrCode]),
        session: Some(MdocBleHolderInteractionSessionData {
            sk_device: SkDevice::new(SecretSlice::from(vec![0; 32])),
            sk_reader: SkReader::new(SecretSlice::from(vec![0; 32])),
            device_request_bytes,
            device_address: "test address".to_string(),
            mtu: 512,
            session_transcript_bytes: vec![],
        }),
    })
    .unwrap();
    let credential_schema_id = Uuid::new_v4().into();
    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "ISO_MDL".to_string(),
        transport: "BLE".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Pending,
        role: ProofRole::Verifier,
        requested_date: Some(crate::clock::now_utc()),
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            imported_source_url: Some("CORE_URL".to_string()),
            last_modified: crate::clock::now_utc(),
            deleted_at: None,
            name: "".to_string(),
            expire_duration: 0,
            input_schemas: Some(vec![ProofInputSchema {
                claim_schemas: None,
                credential_schema: Some(CredentialSchema {
                    batch_size: None,
                    allow_revocation: None,
                    id: credential_schema_id,
                    created_date: crate::clock::now_utc(),
                    imported_source_url: "CORE_URL".to_string(),
                    last_modified: crate::clock::now_utc(),
                    deleted_at: None,
                    name: "".to_string(),
                    formats: vec![CredentialSchemaFormat {
                        id: Uuid::new_v4().into(),
                        created_date: crate::clock::now_utc(),
                        last_modified: crate::clock::now_utc(),
                        credential_schema_id,
                        format: "".into(),
                        schema_id,
                        claim_mappings: Default::default(),
                    }]
                    .into(),
                    revocation_method: None,
                    key_storage_security: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    claim_schemas: Default::default(),
                    organisation: dummy_organisation(Some(organisation_id)).into(),
                    allow_suspension: true,
                    requires_wallet_instance_attestation: false,
                    transaction_code: None,
                    translations: Default::default(),
                    embedded_disclosure_policy: None,
                }),
            }]),
            organisation: None,
        }),
        claims: None,
        verifier_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: Some(Interaction {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            data: Some(interaction_data),
            last_modified: crate::clock::now_utc(),
            organisation: None,
            nonce_id: None,
            interaction_type: InteractionType::Verification,
            expires_at: None,
        }),
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
    };

    let result = provider.holder_reject_proof(&proof).await;
    assert!(result.is_ok(), "Reject proof should succeed");
}

#[tokio::test]
async fn test_get_presentation_definition_ok() {
    let organisation_id = Uuid::new_v4().into();
    let schema_id = "org.iso.18013.5.1".to_string();
    let device_request_bytes = to_cbor(&DeviceRequest {
        version: "1.0".to_string(),
        doc_requests: vec![DocRequest {
            items_request: EmbeddedCbor::new(ItemsRequest {
                doc_type: schema_id.clone(),
                name_spaces: hashmap! {
                    "org.iso.18013.5.1.mDL".to_string() => hashmap! {
                        "name".to_string() => true,
                        "age".to_string() => true,
                        "country".to_string() => true,
                        "info".to_string() => true,
                    }
                },
            })
            .unwrap(),
        }],
    })
    .unwrap();

    let interaction_data = serde_json::to_value(MdocBleHolderInteractionData {
        service_uuid: Uuid::new_v4(),
        continuation_task_id: Uuid::new_v4(),
        engagement: HashSet::from([VerificationEngagement::QrCode]),
        organisation_id,
        session: Some(MdocBleHolderInteractionSessionData {
            sk_device: SkDevice::new(SecretSlice::from(vec![0; 32])),
            sk_reader: SkReader::new(SecretSlice::from(vec![0; 32])),
            device_request_bytes,
            device_address: "test address".to_string(),
            mtu: 512,
            session_transcript_bytes: vec![],
        }),
    })
    .unwrap();

    let proof_id = Uuid::new_v4().into();
    let proof = Proof {
        id: proof_id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "ISO_MDL".to_string(),
        transport: "BLE".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Pending,
        role: ProofRole::Holder,
        requested_date: Some(crate::clock::now_utc()),
        completed_date: None,
        schema: None,
        claims: None,
        verifier_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
    };

    let credential_id = Uuid::new_v4().into();
    let credential_schema_id = Uuid::new_v4().into();

    let claim_schemas = hashmap![
       "org.iso.18013.5.1.mDL" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,        translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL/name" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL/name".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,        translations: Default::default(),
        },
       "org.iso.18013.5.1.mDL/age" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL/age".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,        translations: Default::default(),
        },
       "org.iso.18013.5.1.mDL/country" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL/country".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,        translations: Default::default(),
        },
       "org.iso.18013.5.1.mDL/country_code" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL/country_code".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,        translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL/info" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL/info".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,        translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL/info/code" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL/info/code".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,        translations: Default::default(),
        },
    ];
    let credential_schema = backfill_default_translations(
        CredentialSchema {
            batch_size: None,
            allow_revocation: None,
            id: credential_schema_id,
            created_date: crate::clock::now_utc(),
            imported_source_url: "CORE_URL".to_string(),
            last_modified: crate::clock::now_utc(),
            name: "schema-name".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_id,
                format: "MDOC".into(),
                schema_id,
                claim_mappings: Default::default(),
            }]
            .into(),
            revocation_method: None,
            layout_type: LayoutType::Card,
            organisation: dummy_organisation(Some(organisation_id)).into(),
            layout_properties: None,
            claim_schemas: claim_schemas.values().cloned().collect::<Vec<_>>().into(),
            key_storage_security: None,
            deleted_at: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        },
        "en",
    )
    .await
    .unwrap();

    let claims = vec![
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL/name"].clone()),
            path: "org.iso.18013.5.1.mDL/name".to_string(),
            value: Some("John".to_string()),
            selectively_disclosable: false,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL/age"].clone()),
            path: "org.iso.18013.5.1.mDL/age".to_string(),
            value: Some("55".to_string()),
            selectively_disclosable: false,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL/country"].clone()),
            path: "org.iso.18013.5.1.mDL/country".to_string(),
            value: Some("Germany".to_string()),
            selectively_disclosable: false,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL/country_code"].clone()),
            path: "org.iso.18013.5.1.mDL/country_code".to_string(),
            value: Some("DE".to_string()),
            selectively_disclosable: false,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL/info/code"].clone()),
            path: "org.iso.18013.5.1.mDL/info/code".to_string(),
            value: Some("ABCDEFG".to_string()),
            selectively_disclosable: false,
        },
    ];

    let credential = Credential {
        id: credential_id,
        created_date: crate::clock::now_utc(),
        issuance_date: None,
        last_modified: crate::clock::now_utc(),
        protocol: "ISO_MDL".to_string(),
        schema: Some(credential_schema),
        role: CredentialRole::Holder,
        deleted_at: None,
        redirect_uri: None,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: Some(claims),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        interaction: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        consumed_at: None,
        r#type: CredentialType::Single,
        parent: None,
        embedded_disclosure_policy: None,
    };

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential_list()
        .returning({
            let credential = credential.clone();
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential.clone()],
                    total_items: 1,
                    total_pages: 1,
                })
            }
        });
    credential_repository
        .expect_get_credential()
        .return_once(move |_, _| Ok(Some(credential)));

    let service = IsoMdl::new(
        "ISO_MDL".to_string(),
        Arc::new(generic_config().core),
        Arc::new(credential_repository),
        Arc::new(MockPresentationFormatterProvider::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockCredentialSchemaRepository::new()),
        Arc::new(MockCredentialFormatterProvider::new()),
        Arc::new(MockTrustInformationProvider::new()),
        Arc::new(MockWRPValidator::new()),
        None,
        None,
    );

    let mut presentation_definition = service
        .holder_get_presentation_definition(&proof, interaction_data)
        .await
        .unwrap();

    assert_eq!(1, presentation_definition.request_groups.len());
    let mut request_group = presentation_definition.request_groups.pop().unwrap();

    assert_eq!(proof_id.to_string(), request_group.id);
    assert!(matches!(
        request_group.rule.r#type,
        PresentationDefinitionRuleTypeEnum::All
    ));

    assert_eq!(1, request_group.requested_credentials.len());
    let requested_credential = request_group.requested_credentials.pop().unwrap();

    assert_eq!(1, requested_credential.applicable_credentials.len());
    assert_eq!(
        credential_id,
        requested_credential.applicable_credentials[0]
    );

    let (credentials, mapped_field_ids): (HashSet<CredentialId>, HashSet<String>) =
        requested_credential
            .fields
            .into_iter()
            .flat_map(|field| field.key_map)
            .unzip();

    assert_eq!(hashset![credential_id], credentials);

    assert_eq!(
        mapped_field_ids,
        hashset![
            "org.iso.18013.5.1.mDL/name".into(),
            "org.iso.18013.5.1.mDL/age".into(),
            "org.iso.18013.5.1.mDL/country".into(),
            "org.iso.18013.5.1.mDL/info".into(),
        ]
    )
}

#[tokio::test]
async fn test_get_presentation_definition_v2() {
    let organisation_id = Uuid::new_v4().into();
    let schema_id = "org.iso.18013.5.1".to_string();
    let device_request_bytes = to_cbor(&DeviceRequest {
        version: "1.0".to_string(),
        doc_requests: vec![DocRequest {
            items_request: EmbeddedCbor::new(ItemsRequest {
                doc_type: schema_id.clone(),
                name_spaces: hashmap! {
                    "org.iso.18013.5.1.mDL".to_string() => hashmap! {
                        "name".to_string() => true,
                        "age".to_string() => true,
                        "country".to_string() => true,
                        "info".to_string() => true,
                    }
                },
            })
            .unwrap(),
        }],
    })
    .unwrap();

    let interaction_data = serde_json::to_value(MdocBleHolderInteractionData {
        service_uuid: Uuid::new_v4(),
        continuation_task_id: Uuid::new_v4(),
        engagement: HashSet::from([VerificationEngagement::QrCode]),
        organisation_id,
        session: Some(MdocBleHolderInteractionSessionData {
            sk_device: SkDevice::new(SecretSlice::from(vec![0; 32])),
            sk_reader: SkReader::new(SecretSlice::from(vec![0; 32])),
            device_request_bytes,
            device_address: "test address".to_string(),
            mtu: 512,
            session_transcript_bytes: vec![],
        }),
    })
    .unwrap();

    let proof_id = Uuid::new_v4().into();
    let proof = Proof {
        id: proof_id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "ISO_MDL".to_string(),
        transport: "BLE".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Pending,
        role: ProofRole::Holder,
        requested_date: Some(crate::clock::now_utc()),
        completed_date: None,
        schema: None,
        claims: None,
        verifier_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: Some(Interaction {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            data: Some(interaction_data.to_string().as_bytes().to_vec()),
            organisation: Some(dummy_organisation(Some(organisation_id))),
            nonce_id: None,
            interaction_type: InteractionType::Verification,
            expires_at: None,
        }),
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
    };

    let credential_id = Uuid::new_v4().into();
    let credential_schema_id = Uuid::new_v4().into();

    let claim_schemas = hashmap![
        "org.iso.18013.5.1.mDL_name" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_name".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_age" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_age".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_country" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_country".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_country_code" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_country_code".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_info" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_info".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_info/code" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_info/code".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
    ];
    let credential_schema_format_id = Uuid::new_v4().into();
    let claim_mappings = vec![
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_name"].id,
            technical_key: "name".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_age"].id,
            technical_key: "age".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_country"].id,
            technical_key: "country".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_country_code"].id,
            technical_key: "country_code".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_info"].id,
            technical_key: "info".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_info/code"].id,
            technical_key: "info/code".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
    ];
    let credential_schema = backfill_default_translations(
        CredentialSchema {
            batch_size: None,
            allow_revocation: None,
            id: credential_schema_id,
            created_date: crate::clock::now_utc(),
            imported_source_url: "CORE_URL".to_string(),
            last_modified: crate::clock::now_utc(),
            name: "schema-name".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: credential_schema_format_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_id,
                format: "MDOC".into(),
                schema_id: schema_id.clone(),
                claim_mappings: claim_mappings.into(),
            }]
            .into(),
            revocation_method: None,
            layout_type: LayoutType::Card,
            organisation: dummy_organisation(Some(organisation_id)).into(),
            layout_properties: None,
            claim_schemas: claim_schemas.values().cloned().collect::<Vec<_>>().into(),
            key_storage_security: None,
            deleted_at: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        },
        "en",
    )
    .await
    .unwrap();

    let claims = vec![
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL_name"].clone()),
            path: "org.iso.18013.5.1.mDL_name".to_string(),
            value: Some("John".to_string()),
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL_age"].clone()),
            path: "org.iso.18013.5.1.mDL_age".to_string(),
            value: Some("55".to_string()),
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL_country"].clone()),
            path: "org.iso.18013.5.1.mDL_country".to_string(),
            value: Some("Germany".to_string()),
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL_country_code"].clone()),
            path: "org.iso.18013.5.1.mDL_country_code".to_string(),
            value: Some("DE".to_string()),
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL_info"].clone()),
            path: "org.iso.18013.5.1.mDL_info".to_string(),
            value: None,
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL_info/code"].clone()),
            path: "org.iso.18013.5.1.mDL_info/code".to_string(),
            value: Some("ABCDEFG".to_string()),
            selectively_disclosable: false,
        },
    ];

    let credential = Credential {
        id: credential_id,
        created_date: crate::clock::now_utc(),
        issuance_date: None,
        last_modified: crate::clock::now_utc(),
        protocol: "ISO_MDL".to_string(),
        schema: Some(credential_schema),
        role: CredentialRole::Holder,
        deleted_at: None,
        redirect_uri: None,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: Some(claims),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        interaction: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        consumed_at: None,
        r#type: CredentialType::Single,
        parent: None,
        embedded_disclosure_policy: None,
    };

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential_list()
        .returning({
            let credential = credential.clone();
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential.clone()],
                    total_items: 1,
                    total_pages: 1,
                })
            }
        });
    credential_repository
        .expect_get_credential()
        .return_once(move |_, _| Ok(Some(credential)));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_user_claims_path().return_const(vec![]);

            Ok(Arc::new(formatter))
        });

    let mut trust_information_provider = MockTrustInformationProvider::new();
    trust_information_provider
        .expect_get_trust_purpose()
        .return_once(|_, _| Ok(None));

    let service = IsoMdl::new(
        "ISO_MDL".to_string(),
        Arc::new(generic_config().core),
        Arc::new(credential_repository),
        Arc::new(MockPresentationFormatterProvider::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockCredentialSchemaRepository::new()),
        Arc::new(formatter_provider),
        Arc::new(trust_information_provider),
        Arc::new(MockWRPValidator::new()),
        None,
        None,
    );

    let presentation_definition = service
        .holder_get_presentation_definition_v2(&proof, interaction_data)
        .await
        .unwrap();

    assert_eq!(1, presentation_definition.credential_sets.len());
    assert_eq!(1, presentation_definition.credential_queries.len());
    assert!(
        presentation_definition
            .credential_queries
            .contains_key(&schema_id)
    );

    let credential_query = &presentation_definition.credential_queries[&schema_id];

    assert_eq!(credential_query.multiple, false);
    let ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
        applicable_credentials,
        ..
    } = &credential_query.credential_or_failure_hint
    else {
        panic!("Invalid query");
    };

    assert_eq!(1, applicable_credentials.len());
    assert_eq!(credential_id, applicable_credentials[0].credential.id);
    assert!(
        applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_country" })
    );
    assert!(
        applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_name" })
    );
    assert!(
        applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_age" })
    );
    assert!(
        applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_info" })
    );
    // filtered out because not requested by the proof request
    assert!(
        !applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_country_code" })
    );
}
