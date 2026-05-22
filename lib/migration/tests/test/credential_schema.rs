use sea_orm::DbBackend;

use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_credential_schema() {
    let schema = get_schema().await;

    let mut columns = vec![
        "id",
        "created_date",
        "last_modified",
        "deleted_at",
        "name",
        "format",
        "revocation_method",
        "organisation_id",
        "schema_id",
        "layout_properties",
        "layout_type",
        "imported_source_url",
        "allow_suspension",
        "requires_wallet_instance_attestation",
        "key_storage_security",
        "transaction_code_type",
        "transaction_code_length",
        "transaction_code_description",
        "batch_size",
        "allow_revocation",
    ];
    if schema.backend() == DbBackend::MySql {
        columns.push("deleted_at_materialized");
    }

    let mut index_columns1 = vec!["organisation_id", "schema_id"];
    if schema.backend() == DbBackend::MySql {
        index_columns1.push("deleted_at_materialized")
    } else {
        index_columns1.push("deleted_at")
    }

    let mut index_columns2 = vec!["name", "organisation_id"];
    if schema.backend() == DbBackend::MySql {
        index_columns2.push("deleted_at_materialized")
    } else {
        index_columns2.push("deleted_at")
    }
    let credential_schema = schema
        .table("credential_schema")
        .columns(&columns)
        .index(
            "index-Organisation-SchemaId-DeletedAt-Partial_Unique",
            true,
            &index_columns1,
        )
        .index(
            "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique",
            true,
            &index_columns2,
        )
        .index(
            "index-CredentialSchema-CreatedDate",
            false,
            &["created_date"],
        );
    credential_schema
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    credential_schema
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential_schema
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential_schema
        .column("deleted_at")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    credential_schema
        .column("name")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential_schema
        .column("format")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential_schema
        .column("revocation_method")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential_schema
        .column("organisation_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key("fk-CredentialSchema-OrganisationId", "organisation", "id");
    credential_schema
        .column("schema_id")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential_schema
        .column("layout_properties")
        .r#type(ColumnType::JsonBinary)
        .nullable(true);
    credential_schema
        .column("layout_type")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential_schema
        .column("imported_source_url")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential_schema
        .column("allow_suspension")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    credential_schema
        .column("requires_wallet_instance_attestation")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    credential_schema
        .column("key_storage_security")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential_schema
        .column("transaction_code_type")
        .r#type(ColumnType::String(None))
        .nullable(true);
    credential_schema
        .column("transaction_code_length")
        .r#type(ColumnType::Integer)
        .nullable(true);
    credential_schema
        .column("transaction_code_description")
        .r#type(ColumnType::String(Some(300)))
        .nullable(true);
    credential_schema
        .column("batch_size")
        .r#type(ColumnType::Integer)
        .nullable(true);
}

#[tokio::test]
async fn test_db_schema_claim_schema() {
    let schema = get_schema().await;

    let claim_schema = schema.table("claim_schema").columns(&[
        "id",
        "created_date",
        "last_modified",
        "key",
        "business_key",
        "datatype",
        "array",
        "metadata",
        "credential_schema_id",
        "required",
        "order",
    ]);
    claim_schema
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    claim_schema
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    claim_schema
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    claim_schema
        .column("key")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    claim_schema
        .column("business_key")
        .r#type(ColumnType::String(None))
        .nullable(true);
    claim_schema
        .column("datatype")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    claim_schema
        .column("array")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    claim_schema
        .column("metadata")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    claim_schema
        .column("credential_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk_claim_schema_credential_schema_id",
            "credential_schema",
            "id",
        );
    claim_schema
        .column("required")
        .r#type(ColumnType::Boolean)
        .nullable(false)
        .default(None);
    claim_schema
        .column("order")
        .r#type(ColumnType::Integer)
        .nullable(false)
        .default(None);
}

#[tokio::test]
async fn test_db_schema_credential_schema_format() {
    let schema = get_schema().await;

    let columns = vec![
        "id",
        "created_date",
        "last_modified",
        "credential_schema_id",
        "format",
        "schema_id",
    ];

    let credential_schema_format = schema
        .table("credential_schema_format")
        .columns(&columns)
        .index(
            "index-CredentialSchemaFormat-CredentialSchemaId-Format_Unique",
            true,
            &["credential_schema_id", "format"],
        )
        .index(
            "index-CredentialSchemaFormat-CredentialSchemaId-SchemaId_Unique",
            true,
            &["credential_schema_id", "schema_id"],
        );
    credential_schema_format
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    credential_schema_format
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential_schema_format
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    credential_schema_format
        .column("credential_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-CredentialSchemaFormat-CredentialSchemaId",
            "credential_schema",
            "id",
        );
    credential_schema_format
        .column("format")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    credential_schema_format
        .column("schema_id")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
}

#[tokio::test]
async fn test_db_schema_credential_schema_format_claim_schema() {
    let schema = get_schema().await;

    let columns = vec![
        "id",
        "created_date",
        "last_modified",
        "credential_schema_format_id",
        "claim_schema_id",
        "technical_key",
        "namespace",
    ];

    let cs_format_claim = schema
        .table("credential_schema_format_claim_schema")
        .columns(&columns)
        .index(
            "index-FormatClaimSchema-FormatId-ClaimSchemaId_Unique",
            true,
            &["credential_schema_format_id", "claim_schema_id"],
        );
    cs_format_claim
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    cs_format_claim
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    cs_format_claim
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    cs_format_claim
        .column("credential_schema_format_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-CredentialSchemaFormatClaimSchema-CredentialSchemaFormatId",
            "credential_schema_format",
            "id",
        );
    cs_format_claim
        .column("claim_schema_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .foreign_key(
            "fk-CredentialSchemaFormatClaimSchema-ClaimSchemaId",
            "claim_schema",
            "id",
        );
    cs_format_claim
        .column("technical_key")
        .r#type(ColumnType::String(None))
        .nullable(false)
        .default(None);
    cs_format_claim
        .column("namespace")
        .r#type(ColumnType::String(None))
        .nullable(true);
}
