use std::sync::Arc;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema,
    CredentialSchemaListQuery, KeyStorageSecurity, LayoutProperties, LayoutType, LogoProperties,
    TransactionCode,
};
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use one_core::model::organisation::Organisation;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use shared_types::{ClaimSchemaId, CredentialFormat, CredentialSchemaId, RevocationMethodId};
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Default, Clone)]
pub struct TestingCreateSchemaParams {
    pub id: Option<CredentialSchemaId>,
    pub schema_id: Option<String>,
    pub format: Option<CredentialFormat>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub allow_suspension: Option<bool>,
    pub imported_source_url: Option<String>,
    pub claim_schemas: Option<Vec<ClaimSchema>>,
    pub requires_wallet_instance_attestation: bool,
    pub deleted_at: Option<OffsetDateTime>,
    pub transaction_code: Option<TransactionCode>,
    pub batch_size: Option<i32>,
}

fn claim_name_translation(id: ClaimSchemaId, key: &str) -> LocalizedText {
    let name = key.rsplit('/').next().unwrap_or(key).to_owned();
    LocalizedText {
        entity_id: id.into(),
        field: LocalizedTextField::Name,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        lang: "en".to_string(),
        value: name,
        entity_type: LocalizedTextEntityType::ClaimSchema,
    }
}

pub struct CredentialSchemasDB {
    repository: Arc<dyn CredentialSchemaRepository>,
}

impl CredentialSchemasDB {
    pub fn new(repository: Arc<dyn CredentialSchemaRepository>) -> Self {
        Self { repository }
    }

    pub async fn create_with_result(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: impl Into<Option<RevocationMethodId>>,
        params: TestingCreateSchemaParams,
    ) -> Result<CredentialSchema, DataLayerError> {
        let claim_schemas = params.claim_schemas.unwrap_or_else(|| {
            let claim_schema = ClaimSchema {
                business_key: None,
                id: Uuid::new_v4().into(),
                key: "firstName".to_string(),
                data_type: "STRING".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
                metadata: false,
                required: true,
                translations: Default::default(),
            };
            let claim_schema1 = ClaimSchema {
                business_key: None,
                id: Uuid::new_v4().into(),
                key: "isOver18".to_string(),
                data_type: "BOOLEAN".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
                metadata: false,
                required: false,
                translations: Default::default(),
            };
            vec![claim_schema, claim_schema1]
        });

        let id = params.id.unwrap_or(Uuid::new_v4().into());
        let mut credential_schema = CredentialSchema {
            batch_size: params.batch_size,
            allow_revocation: None,
            id,
            imported_source_url: params.imported_source_url.unwrap_or("CORE_URL".to_string()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            key_storage_security: params.key_storage_security,
            organisation: organisation.clone().into(),
            deleted_at: params.deleted_at,
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                credential_schema_id: id,
                format: params.format.unwrap_or("JWT".into()),
                schema_id: params.schema_id.unwrap_or_else(|| id.to_string()),
                claim_mappings: Default::default(),
            }]
            .into(),
            revocation_method: revocation_method.into(),
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: Some(LayoutProperties {
                primary_attribute: Some("firstName".to_owned()),
                secondary_attribute: Some("firstName".to_owned()),
                background: Some(BackgroundProperties {
                    color: Some("#DA2727".to_owned()),
                    image: None,
                }),
                logo: Some(LogoProperties {
                    font_color: Some("#DA2727".to_owned()),
                    background_color: Some("#DA2727".to_owned()),
                    image: None,
                }),
                picture_attribute: Some("firstName".to_owned()),
                code: Some(CodeProperties {
                    attribute: "firstName".to_owned(),
                    r#type: CodeTypeEnum::Barcode,
                }),
            }),
            allow_suspension: params.allow_suspension.unwrap_or(true),
            requires_wallet_instance_attestation: params.requires_wallet_instance_attestation,
            transaction_code: params.transaction_code,
            translations: Default::default(),
        };

        add_default_translations(&mut credential_schema).await?;
        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await?;
        Ok(self.get(&id).await)
    }

    pub async fn create(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: impl Into<Option<RevocationMethodId>>,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        self.create_with_result(name, organisation, revocation_method, params)
            .await
            .unwrap()
    }

    pub async fn create_special_chars(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: impl Into<Option<RevocationMethodId>>,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let id = Uuid::new_v4();
        let claim_schema = ClaimSchema {
            business_key: None,
            id: Uuid::new_v4().into(),
            key: "first name#".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        };
        let claim_schemas = vec![claim_schema.to_owned()];

        let mut credential_schema = CredentialSchema {
            batch_size: params.batch_size,
            allow_revocation: None,
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            key_storage_security: params.key_storage_security,
            organisation: organisation.clone().into(),
            deleted_at: None,
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                credential_schema_id: id.into(),
                format: params.format.unwrap_or("JSON_LD_BBSPLUS".into()),
                schema_id: id.to_string(),
                claim_mappings: Default::default(),
            }]
            .into(),
            revocation_method: revocation_method.into(),
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
        };

        add_default_translations(&mut credential_schema)
            .await
            .unwrap();
        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_array_claims(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: impl Into<Option<RevocationMethodId>>,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let claim_schema_root_namespace: ClaimSchema = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "namespace".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_root_field: ClaimSchema = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "namespace/root_field".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_root_array = ClaimSchema {
            business_key: None,
            array: true,
            id: Uuid::new_v4().into(),
            key: "namespace/root_array".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            metadata: false,
            required: true,
            translations: Default::default(),
        };
        let claim_schema_nested = ClaimSchema {
            business_key: None,
            array: true,
            id: Uuid::new_v4().into(),
            key: "namespace/root_array/nested".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            metadata: false,
            required: true,
            translations: Default::default(),
        };
        let claim_schema_field = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "namespace/root_array/nested/field".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schemas = vec![
            claim_schema_root_namespace.to_owned(),
            claim_schema_root_field.to_owned(),
            claim_schema_root_array.to_owned(),
            claim_schema_nested.to_owned(),
            claim_schema_field.to_owned(),
        ];

        let id = Uuid::new_v4();
        let mut credential_schema = CredentialSchema {
            batch_size: params.batch_size,
            allow_revocation: None,
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            key_storage_security: params.key_storage_security,
            organisation: organisation.clone().into(),
            deleted_at: None,
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                credential_schema_id: id.into(),
                format: params.format.unwrap_or("JWT".into()),
                schema_id: params.schema_id.unwrap_or("doctype".to_string()),
                claim_mappings: Default::default(),
            }]
            .into(),
            revocation_method: revocation_method.into(),
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
        };

        add_default_translations(&mut credential_schema)
            .await
            .unwrap();
        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_nested_claims(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: impl Into<Option<RevocationMethodId>>,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let claim_schema_address = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_street = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/street".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_coordinates = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_coordinates_x = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/x".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_coordinates_y = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/y".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schemas = vec![
            claim_schema_address.to_owned(),
            claim_schema_address_street.to_owned(),
            claim_schema_address_coordinates.to_owned(),
            claim_schema_address_coordinates_x.to_owned(),
            claim_schema_address_coordinates_y.to_owned(),
        ];

        let id = Uuid::new_v4();
        let mut credential_schema = CredentialSchema {
            batch_size: params.batch_size,
            allow_revocation: None,
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            key_storage_security: params.key_storage_security,
            organisation: organisation.clone().into(),
            deleted_at: None,
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                credential_schema_id: id.into(),
                format: params.format.unwrap_or("JWT".into()),
                schema_id: format!("ssi/schema/{id}"),
                claim_mappings: Default::default(),
            }]
            .into(),
            revocation_method: revocation_method.into(),
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
        };

        add_default_translations(&mut credential_schema)
            .await
            .unwrap();
        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_nested_claims_and_root_field(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: impl Into<Option<RevocationMethodId>>,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let claim_schema_name = ClaimSchema {
            business_key: None,
            id: Uuid::new_v4().into(),
            key: "name".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_street = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/street".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_coordinates = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_coordinates_x = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/x".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_coordinates_y = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/y".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schemas = vec![
            claim_schema_name.to_owned(),
            claim_schema_address.to_owned(),
            claim_schema_address_street.to_owned(),
            claim_schema_address_coordinates.to_owned(),
            claim_schema_address_coordinates_x.to_owned(),
            claim_schema_address_coordinates_y.to_owned(),
        ];

        let id = Uuid::new_v4();
        let mut credential_schema = CredentialSchema {
            batch_size: params.batch_size,
            allow_revocation: None,
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            key_storage_security: params.key_storage_security,
            organisation: organisation.clone().into(),
            deleted_at: None,
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                credential_schema_id: id.into(),
                format: params.format.unwrap_or("JWT".into()),
                schema_id: format!("ssi/schema/{id}"),
                claim_mappings: Default::default(),
            }]
            .into(),
            revocation_method: revocation_method.into(),
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
        };

        add_default_translations(&mut credential_schema)
            .await
            .unwrap();
        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_nested_hell(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: impl Into<Option<RevocationMethodId>>,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let claim_schema_name_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_name = ClaimSchema {
            business_key: None,
            id: claim_schema_name_id,
            key: "name".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: true,
            translations: vec![claim_name_translation(claim_schema_name_id, "name")].into(),
        };
        let claim_schema_string_array_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_string_array = ClaimSchema {
            business_key: None,
            id: claim_schema_string_array_id,
            key: "string_array".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
            metadata: false,
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_string_array_id,
                "string_array",
            )]
            .into(),
        };
        let claim_schema_object_array = ClaimSchema {
            business_key: None,
            id: Uuid::new_v4().into(),
            key: "object_array".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
            metadata: false,
            required: true,
            translations: Default::default(),
        };
        let claim_schema_object_array_field1_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_object_array_field1 = ClaimSchema {
            business_key: None,
            id: claim_schema_object_array_field1_id,
            key: "object_array/field1".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_object_array_field1_id,
                "object_array/field1",
            )]
            .into(),
        };
        let claim_schema_object_array_field2_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_object_array_field2 = ClaimSchema {
            business_key: None,
            id: claim_schema_object_array_field2_id,
            key: "object_array/field2".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_object_array_field2_id,
                "object_array/field2",
            )]
            .into(),
        };
        let claim_schema_address = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_address_street_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_address_street = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: claim_schema_address_street_id,
            key: "address/street".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_address_street_id,
                "address/street",
            )]
            .into(),
        };
        let claim_schema_address_coordinates = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schema_nested_string_array_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_nested_string_array = ClaimSchema {
            business_key: None,
            id: claim_schema_nested_string_array_id,
            key: "address/coordinates/string_array".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
            metadata: false,
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_nested_string_array_id,
                "address/coordinates/string_array",
            )]
            .into(),
        };
        let claim_schema_nested_object_array = ClaimSchema {
            business_key: None,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/object_array".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
            metadata: false,
            required: true,
            translations: Default::default(),
        };
        let claim_schema_nested_object_array_field1_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_nested_object_array_field1 = ClaimSchema {
            business_key: None,
            id: claim_schema_nested_object_array_field1_id,
            key: "address/coordinates/object_array/field1".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_nested_object_array_field1_id,
                "address/coordinates/object_array/field1",
            )]
            .into(),
        };
        let claim_schema_nested_object_array_field2_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_nested_object_array_field2 = ClaimSchema {
            business_key: None,
            id: claim_schema_nested_object_array_field2_id,
            key: "address/coordinates/object_array/field2".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_nested_object_array_field2_id,
                "address/coordinates/object_array/field2",
            )]
            .into(),
        };
        let claim_schema_address_coordinates_x_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_address_coordinates_x = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: claim_schema_address_coordinates_x_id,
            key: "address/coordinates/x".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_address_coordinates_x_id,
                "address/coordinates/x",
            )]
            .into(),
        };
        let claim_schema_address_coordinates_y_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema_address_coordinates_y = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: claim_schema_address_coordinates_y_id,
            key: "address/coordinates/y".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: vec![claim_name_translation(
                claim_schema_address_coordinates_y_id,
                "address/coordinates/y",
            )]
            .into(),
        };
        let claim_schemas = vec![
            claim_schema_name.to_owned(),
            claim_schema_string_array.to_owned(),
            claim_schema_object_array.to_owned(),
            claim_schema_object_array_field1.to_owned(),
            claim_schema_object_array_field2.to_owned(),
            claim_schema_address.to_owned(),
            claim_schema_address_street.to_owned(),
            claim_schema_address_coordinates.to_owned(),
            claim_schema_nested_string_array.to_owned(),
            claim_schema_nested_object_array.to_owned(),
            claim_schema_nested_object_array_field1.to_owned(),
            claim_schema_nested_object_array_field2.to_owned(),
            claim_schema_address_coordinates_x.to_owned(),
            claim_schema_address_coordinates_y.to_owned(),
        ];

        let id = Uuid::new_v4();
        let mut credential_schema = CredentialSchema {
            batch_size: params.batch_size,
            allow_revocation: None,
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            key_storage_security: params.key_storage_security,
            organisation: organisation.clone().into(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                credential_schema_id: id.into(),
                format: params.format.unwrap_or("JWT".into()),
                schema_id: format!("ssi/schema/{id}"),
                claim_mappings: Default::default(),
            }]
            .into(),
            deleted_at: None,
            revocation_method: revocation_method.into(),
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: params.requires_wallet_instance_attestation,
            transaction_code: None,
            translations: Default::default(),
        };

        add_default_translations(&mut credential_schema)
            .await
            .unwrap();
        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_picture_claim(
        &self,
        name: &str,
        organisation: &Organisation,
    ) -> CredentialSchema {
        let claim_schema = ClaimSchema {
            business_key: None,
            array: false,
            metadata: false,
            id: Uuid::new_v4().into(),
            key: "firstName".to_string(),
            data_type: "PICTURE".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            required: true,
            translations: Default::default(),
        };
        let claim_schemas = vec![claim_schema.to_owned()];

        let new_id = Uuid::new_v4();
        let mut credential_schema = CredentialSchema {
            batch_size: None,
            allow_revocation: None,
            id: new_id.into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            key_storage_security: None,
            name: name.to_owned(),
            organisation: organisation.clone().into(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                credential_schema_id: new_id.into(),
                format: "JWT".into(),
                schema_id: "new_id.to_string()".to_owned(),
                claim_mappings: Default::default(),
            }]
            .into(),
            deleted_at: None,
            revocation_method: None,
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
        };

        add_default_translations(&mut credential_schema)
            .await
            .unwrap();
        let id = self
            .repository
            .create_credential_schema(credential_schema.clone())
            .await
            .unwrap();

        self.get(&id).await
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn create_with_claims(
        &self,
        id: &Uuid,
        name: &str,
        organisation: &Organisation,
        revocation_method: impl Into<Option<RevocationMethodId>>,
        new_claim_schemas: &[(Uuid, &str, bool, &str, bool)],
        format: &str,
        schema_id: &str,
    ) -> CredentialSchema {
        let claim_schemas: Vec<_> = new_claim_schemas
            .iter()
            .map(|(id, name, required, data_type, array)| ClaimSchema {
                business_key: None,
                id: (*id).into(),
                key: name.to_string(),
                data_type: data_type.to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: *array,
                metadata: false,
                required: *required,
                translations: Default::default(),
            })
            .collect();

        let mut credential_schema = CredentialSchema {
            batch_size: None,
            allow_revocation: None,
            id: id.to_owned().into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            key_storage_security: None,
            name: name.to_owned(),
            organisation: organisation.clone().into(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                credential_schema_id: id.to_owned().into(),
                format: format.into(),
                schema_id: schema_id.to_owned(),
                claim_mappings: Default::default(),
            }]
            .into(),
            deleted_at: None,
            revocation_method: revocation_method.into(),
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: Some(LayoutProperties {
                background: Some(BackgroundProperties {
                    color: Some("color".to_string()),
                    image: None,
                }),
                logo: None,
                primary_attribute: None,
                secondary_attribute: None,
                picture_attribute: None,
                code: None,
            }),
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
        };

        add_default_translations(&mut credential_schema)
            .await
            .unwrap();
        let id = self
            .repository
            .create_credential_schema(credential_schema.clone())
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_multiformat(
        &self,
        name: &str,
        organisation: &Organisation,
        batch_size: Option<i32>,
    ) -> Result<CredentialSchemaId, DataLayerError> {
        let claim_schema_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema = ClaimSchema {
            business_key: None,
            id: claim_schema_id,
            key: "firstName".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: true,
            translations: vec![claim_name_translation(claim_schema_id, "firstName")].into(),
        };
        let claim_schema1_id: ClaimSchemaId = Uuid::new_v4().into();
        let claim_schema1 = ClaimSchema {
            business_key: None,
            id: claim_schema1_id,
            key: "isOver18".to_string(),
            data_type: "BOOLEAN".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
            required: false,
            translations: vec![claim_name_translation(claim_schema1_id, "isOver18")].into(),
        };
        let claim_schemas = vec![claim_schema, claim_schema1];

        let id = Uuid::new_v4().into();
        let credential_schema = CredentialSchema {
            batch_size,
            allow_revocation: None,
            id,
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            key_storage_security: None,
            organisation: organisation.clone().into(),
            deleted_at: None,
            formats: vec![
                CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: one_core::clock::now_utc(),
                    last_modified: one_core::clock::now_utc(),
                    credential_schema_id: id,
                    format: "SD_JWT_VC".into(),
                    schema_id: "sd-jwt_vct".to_string(),
                    claim_mappings: Default::default(),
                },
                CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: one_core::clock::now_utc(),
                    last_modified: one_core::clock::now_utc(),
                    credential_schema_id: id,
                    format: "MDOC".into(),
                    schema_id: "mdoc_doctype".to_string(),
                    claim_mappings: Default::default(),
                },
            ]
            .into(),
            revocation_method: None,
            claim_schemas: claim_schemas.into(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            allow_suspension: false,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
        };

        self.repository
            .create_credential_schema(credential_schema)
            .await
    }

    pub async fn get(&self, credential_schema_id: &CredentialSchemaId) -> CredentialSchema {
        self.repository
            .get_credential_schema(credential_schema_id)
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn delete(&self, credential_schema: &CredentialSchema) {
        self.repository
            .delete_credential_schema(credential_schema)
            .await
            .unwrap();
    }

    pub async fn list(&self) -> Vec<CredentialSchema> {
        let response = self
            .repository
            .get_credential_schema_list(CredentialSchemaListQuery {
                pagination: None,
                sorting: None,
                filtering: None,
                include: Some(vec![
                    CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
                ]),
            })
            .await
            .unwrap();
        response.values
    }
}

pub async fn add_default_translations(schema: &mut CredentialSchema) -> Result<(), DataLayerError> {
    let now = get_dummy_date();
    schema.translations = vec![LocalizedText {
        entity_id: schema.id.into(),
        field: LocalizedTextField::Name,
        created_date: now,
        last_modified: now,
        lang: "en".to_string(),
        value: schema.name.clone(),
        entity_type: LocalizedTextEntityType::CredentialSchema,
    }]
    .into();

    let mut claim_schemas = schema.claim_schemas.as_mut().await?;
    for cs in claim_schemas.iter_mut() {
        if !cs.metadata {
            let label = cs
                .key
                .rsplit_once('/')
                .map(|(_, end)| end)
                .unwrap_or(&cs.key)
                .to_string();
            cs.translations = vec![LocalizedText {
                entity_id: cs.id.into(),
                field: LocalizedTextField::Name,
                created_date: now,
                last_modified: now,
                lang: "en".to_string(),
                value: label,
                entity_type: LocalizedTextEntityType::ClaimSchema,
            }]
            .into();
        }
    }

    Ok(())
}
