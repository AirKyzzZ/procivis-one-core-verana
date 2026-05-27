#![allow(unused_imports)]

pub mod blob;
pub mod certificate;
pub mod claim;
pub mod claim_schema;
pub mod credential;
pub mod credential_schema;
pub mod credential_schema_format;
pub mod credential_schema_format_claim_schema;
pub mod did;
pub mod history;
pub mod holder_wallet_instance;
pub mod identifier;
pub mod identifier_trust_information;
pub mod interaction;
pub mod key;
pub mod key_did;
pub mod localized_text;
pub mod notification;
pub mod organisation;
pub mod proof;
pub mod proof_claim;
pub mod proof_input_claim_schema;
pub mod proof_input_schema;
pub mod proof_schema;
pub mod remote_entity_cache;
pub mod revocation_list;
pub mod revocation_list_entry;
pub mod trust_collection;
pub mod trust_entry;
pub mod trust_list_publication;
pub mod trust_list_subscription;
pub mod verifier_instance;
pub mod wallet_instance;
pub mod wallet_instance_attestation;
pub mod wallet_instance_attested_key;

pub use identifier::{
    ActiveModel as IdentifierActiveModel, Column as IdentifierColumn, Entity as IdentifierEntity,
    Model as IdentifierModel, Relation as IdentifierRelation,
};
