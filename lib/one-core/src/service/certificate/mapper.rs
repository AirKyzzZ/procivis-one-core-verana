use one_dto_mapper::convert_inner;

use super::dto::CertificateResponseDTO;
use super::error::CertificateServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::certificate::Certificate;
use crate::proto::certificate_validator::parse::parse_chain_to_x509_attributes;

pub(crate) async fn certificate_to_response_dto(
    certificate: Certificate,
) -> Result<CertificateResponseDTO, CertificateServiceError> {
    let key = match certificate.key {
        Some(key) => Some(key.as_ref().await?.to_owned()),
        None => None,
    };
    let x509_attributes = parse_chain_to_x509_attributes(certificate.chain.as_bytes())
        .error_while("parsing PEM chain")?;
    Ok(CertificateResponseDTO {
        id: certificate.id,
        identifier_id: certificate.identifier_id,
        created_date: certificate.created_date,
        last_modified: certificate.last_modified,
        state: certificate.state,
        name: certificate.name,
        chain: certificate.chain,
        key: convert_inner(key),
        x509_attributes,
        organisation_id: certificate.organisation.as_ref().map(|o| o.id()),
        roles: certificate.roles,
    })
}
