use one_core::model::localized_text::{LocalizedTextEntityType, LocalizedTextField};
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_import_credential_schema_v2_with_translations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [
            {
              "array": false,
              "claims": [],
              "createdDate": "2026-05-18T13:53:49.979Z",
              "datatype": "STRING",
              "id": "ac18f142-50c4-4878-802a-7e3245ac0d05",
              "key": "firstName",
              "lastModified": "2026-05-18T13:53:49.979Z",
              "mappings": [
                {
                  "format": "JWT",
                  "technicalKey": "root/firstName"
                }
              ],
              "required": true,
              "translations": {
                "name": {
                  "en": "firstName"
                }
              }
            }
          ],
          "createdDate": "2026-05-18T13:53:49.979Z",
          "datatype": "OBJECT",
          "id": "ef625d50-b816-43ce-b69b-2f5fc6cc59c8",
          "key": "root",
          "lastModified": "2026-05-18T13:53:49.979Z",
          "mappings": [
            {
              "format": "JWT",
              "technicalKey": "root"
            }
          ],
          "required": true,
          "translations": {
            "name": {
              "en": "root"
            }
          }
        }
      ],
      "createdDate": "2026-05-18T13:53:49.979Z",
      "formats": [
        {
          "format": "JWT",
          "schemaId": "7812e9af-523d-4892-8fb2-fe67101a5ffe"
        }
      ],
      "id": "7812e9af-523d-4892-8fb2-fe67101a5ffe",
      "importedSourceUrl": "http://127.0.0.1:51147/ssi/schema/v2/6b457c8b-5af4-4fd9-9767-c87349675dd2",
      "lastModified": "2026-05-18T13:53:49.979Z",
      "layoutProperties": {
        "background": {
          "color": "bg-color"
        },
        "primaryAttribute": "root/firstName"
      },
      "layoutType": "CARD",
      "name": "exportable schema",
      "organisationId": "b6bb4b89-8e70-48b3-9ff7-e8e9c44904e7",
      "requiresWalletInstanceAttestation": false,
      "translations": {
        "description": {
          "de": "Ein Schema zum Importieren",
          "en": "A schema for import"
        },
        "name": {
          "de": "Importierbares Schema",
          "en": "Importable schema"
        }
      }
    });

    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 201);
    let imported_id = import_resp.json_value().await["id"].parse();
    let imported_schema = context.db.credential_schemas.get(&imported_id).await;
    let imported_schema_translations = context.db.localized_text.get(imported_schema.id).await;
    let name_translations: Vec<_> = imported_schema_translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .collect();
    assert_eq!(name_translations.len(), 2);
    assert!(
        name_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "Importable schema")
    );
    assert!(
        name_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Importierbares Schema")
    );
    let description_translations: Vec<_> = imported_schema_translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Description)
        .collect();
    assert_eq!(description_translations.len(), 2);
    assert!(
        description_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "A schema for import")
    );
    assert!(
        description_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Ein Schema zum Importieren")
    );
    assert!(
        imported_schema_translations
            .iter()
            .all(|t| t.entity_type == LocalizedTextEntityType::CredentialSchema)
    );
}

#[tokio::test]
async fn test_import_credential_schema_v2_without_translation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [
            {
              "array": false,
              "claims": [],
              "createdDate": "2026-05-18T13:58:17.758Z",
              "datatype": "STRING",
              "id": "13a73121-eb6f-4ffd-97f5-a9d9a0ec3597",
              "key": "firstName",
              "lastModified": "2026-05-18T13:58:17.758Z",
              "mappings": [
                {
                  "format": "JWT",
                  "technicalKey": "root/firstName"
                }
              ],
              "required": true,
              "translations": {
                "name": {
                  "en": "firstName"
                }
              }
            }
          ],
          "createdDate": "2026-05-18T13:58:17.758Z",
          "datatype": "OBJECT",
          "id": "355107ca-9872-4f09-b30a-647b8006b308",
          "key": "root",
          "lastModified": "2026-05-18T13:58:17.758Z",
          "mappings": [
            {
              "format": "JWT",
              "technicalKey": "root"
            }
          ],
          "required": true,
          "translations": {
            "name": {
              "en": "root"
            }
          }
        }
      ],
      "createdDate": "2026-05-18T13:58:17.758Z",
      "formats": [
        {
          "format": "JWT",
          "schemaId": "ab3f4837-0a50-4218-bd90-6d0e60671946"
        }
      ],
      "id": "ab3f4837-0a50-4218-bd90-6d0e60671946",
      "importedSourceUrl": "http://127.0.0.1:51170/ssi/schema/v2/4842afb9-26e6-4e83-a651-a57b4521b832",
      "lastModified": "2026-05-18T13:58:17.758Z",
      "layoutProperties": {
        "background": {
          "color": "bg-color"
        },
        "primaryAttribute": "root/firstName"
      },
      "layoutType": "CARD",
      "name": "plain schema",
      "organisationId": "ca7493bb-2ae4-49b9-b26c-c0485e98f2d9",
      "requiresWalletInstanceAttestation": false
    }
        );
    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 201);
    let imported_id = import_resp.json_value().await["id"].parse();
    let imported_schema = context.db.credential_schemas.get(&imported_id).await;
    let imported_schema_translations = context.db.localized_text.get(imported_schema.id).await;
    let name_translations: Vec<_> = imported_schema_translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .collect();
    assert_eq!(name_translations.len(), 1);
    assert_eq!(name_translations.first().unwrap().lang, "en");
    assert_eq!(name_translations.first().unwrap().value, "plain schema");
}
