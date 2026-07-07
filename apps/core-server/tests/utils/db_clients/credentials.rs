use std::sync::Arc;

use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRelations, CredentialRole,
    CredentialStateEnum, CredentialType, UpdateCredentialRequest,
};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::identifier::{Identifier, IdentifierRelations};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::repository::credential_repository::CredentialRepository;
use shared_types::CredentialId;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::db_clients::blobs::{BlobsDB, TestingBlobParams};

pub struct CredentialsDB {
    repository: Arc<dyn CredentialRepository>,
}

impl CredentialsDB {
    pub fn new(repository: Arc<dyn CredentialRepository>) -> Self {
        Self { repository }
    }

    pub async fn get(&self, credential_id: &CredentialId) -> Credential {
        self.repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(Default::default()),
                    }),
                    schema: Some(Default::default()),
                    interaction: Some(Default::default()),
                    holder_identifier: Some(IdentifierRelations {
                        ..Default::default()
                    }),
                    key: Some(Default::default()),
                    issuer_identifier: Some(Default::default()),
                    issuer_certificate: Some(Default::default()),
                },
            )
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn list(
        &self,
        filter: ListFilterCondition<CredentialFilterValue>,
    ) -> Vec<Credential> {
        let creds = self
            .repository
            .get_credential_list(CredentialListQuery {
                filtering: Some(filter),
                ..Default::default()
            })
            .await
            .unwrap()
            .values;
        let mut result = vec![];
        for cred in creds {
            result.push(self.get(&cred.id).await);
        }
        result
    }

    pub async fn update(&self, id: CredentialId, update: UpdateCredentialRequest) {
        self.repository.update_credential(id, update).await.unwrap();
    }

    pub async fn create(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_identifier: &Identifier,
        protocol: &str,
        params: TestingCredentialParams,
    ) -> Credential {
        let credential = self
            .prepare_credential(
                credential_schema,
                state,
                issuer_identifier,
                protocol,
                params,
            )
            .await;

        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();

        self.get(&id).await
    }

    async fn prepare_credential(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_identifier: &Identifier,
        protocol: &str,
        params: TestingCredentialParams,
    ) -> Credential {
        let credential_id = params.id.unwrap_or(Uuid::new_v4().into());
        let claim_schemas = credential_schema.claim_schemas.as_ref().await.unwrap();

        let claims = if let Some(claims_data) = params.claims_data {
            claims_data
                .into_iter()
                .map(|new_claim| {
                    let claim_schema = claim_schemas
                        .iter()
                        .find(|schema| schema.id == new_claim.schema_id)
                        .expect("Missing claim schema id");

                    Claim {
                        id: Uuid::new_v4().into(),
                        credential_id,
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        value: new_claim.value,
                        path: new_claim.path,
                        selectively_disclosable: new_claim.selectively_disclosable,
                        schema: Some(claim_schema.to_owned()),
                    }
                })
                .collect()
        } else {
            claim_schemas
                .iter()
                .filter(|claim_schema| claim_schema.data_type != "OBJECT" && !claim_schema.array)
                .flat_map(|claim_schema| {
                    let path = add_intermediary_indices_to_claim_schema_key(
                        &claim_schema.key,
                        &claim_schemas,
                    );
                    if claim_schema.array {
                        vec![
                            Claim {
                                id: Uuid::new_v4().into(),
                                credential_id,
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                value: schema_to_dummy_value(claim_schema, params.random_claims),
                                path: format!("{path}/0"),
                                selectively_disclosable: false,
                                schema: Some(claim_schema.to_owned()),
                            },
                            Claim {
                                id: Uuid::new_v4().into(),
                                credential_id,
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                value: None,
                                path,
                                selectively_disclosable: false,
                                schema: Some(claim_schema.to_owned()),
                            },
                        ]
                    } else {
                        vec![Claim {
                            id: Uuid::new_v4().into(),
                            credential_id,
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            value: schema_to_dummy_value(claim_schema, params.random_claims),
                            path,
                            selectively_disclosable: false,
                            schema: Some(claim_schema.to_owned()),
                        }]
                    }
                })
                .collect()
        };

        let issuance_date = if state == CredentialStateEnum::Accepted {
            Some(get_dummy_date())
        } else {
            None
        };

        Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            issuance_date,
            deleted_at: params.deleted_at,
            consumed_at: params.consumed_at,
            protocol: protocol.to_owned(),
            redirect_uri: None,
            role: params.role.unwrap_or(CredentialRole::Issuer),
            r#type: params.r#type.unwrap_or(CredentialType::Single),
            state,
            suspend_end_date: params.suspend_end_date,
            claims: Some(claims),
            issuer_identifier: Some(issuer_identifier.to_owned()),
            issuer_certificate: params.issuer_certificate.or(issuer_identifier
                .certificates
                .as_ref()
                .and_then(|certs| certs.first().cloned())),
            holder_identifier: params.holder_identifier,
            schema: Some(credential_schema.to_owned()),
            interaction: params.interaction,
            key: params.key,
            profile: params.profile,
            credential_blob_id: params.credential_blob_id,
            wallet_unit_attestation_blob_id: params.wallet_unit_attestation_blob_id,
            wallet_instance_attestation_blob_id: params.wallet_instance_attestation_blob_id,
            webhook_url: params.webhook_url,
            embedded_disclosure_policy: params.embedded_disclosure_policy,
            subscriber_information: None,
            parent: params
                .parent_id
                .map(|id| Related::new(id, self.repository.clone())),
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn create_batch(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_identifier: &Identifier,
        protocol: &str,
        mut params: TestingCredentialParams,
        num_items: usize,
        blob_storage: Option<&BlobsDB>,
    ) -> Credential {
        credential_schema
            .batch_size
            .expect("schema batch size is required to create credential batch");
        let key = params.key.take();
        let holder_identifier = params.holder_identifier.take();
        let mut credential = self
            .prepare_credential(
                credential_schema,
                state,
                issuer_identifier,
                protocol,
                params,
            )
            .await;
        credential.r#type = CredentialType::BatchParent;

        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();
        let batch_item_template = Credential {
            claims: Some(vec![]),
            r#type: CredentialType::BatchItem,
            webhook_url: None,
            parent: Some(Related::new(id, self.repository.clone())),
            interaction: None,
            key,
            holder_identifier,
            ..credential.clone()
        };
        for _ in 0..num_items {
            let credential_blob_id = if let Some(blob_storage) = blob_storage {
                Some(
                    blob_storage
                        .create(TestingBlobParams {
                            value: Some("TOKEN".as_bytes().to_vec()),
                            ..Default::default()
                        })
                        .await
                        .id,
                )
            } else {
                None
            };
            let batch_item_credential = Credential {
                id: Uuid::new_v4().into(),
                credential_blob_id,
                ..batch_item_template.clone()
            };
            self.repository
                .create_credential(batch_item_credential.to_owned())
                .await
                .unwrap();
        }

        self.get(&id).await
    }
}

fn add_intermediary_indices_to_claim_schema_key(
    schema_key: &str,
    schemas: &[ClaimSchema],
) -> String {
    let mut current_schema_key = "".to_string();
    let mut claim_path = vec![];
    for segment in schema_key.split('/') {
        claim_path.push(segment.to_owned());
        current_schema_key += segment;
        if current_schema_key != schema_key // otherwise we're at the end
            && schemas
                .iter()
                .find(|schema| schema.key == current_schema_key)
                .expect("schema not found")
                .array
        {
            claim_path.push("0".to_string())
        }
        current_schema_key += "/";
    }
    claim_path.join("/")
}

fn schema_to_dummy_value(claim_schema: &ClaimSchema, random_claims: bool) -> Option<String> {
    let data_type = &claim_schema.data_type;
    if data_type == "OBJECT" {
        return None;
    }
    let value = match data_type.as_str() {
        "NUMBER" => {
            if random_claims {
                rand::random::<u32>().to_string()
            } else {
                "42".to_string()
            }
        }
        "BOOLEAN" => {
            if random_claims {
                rand::random::<u32>().is_multiple_of(2).to_string()
            } else {
                "true".to_string()
            }
        }
        _ => {
            if random_claims {
                format!("test:{}", Uuid::new_v4())
            } else {
                "test".to_string()
            }
        }
    };
    Some(value)
}
