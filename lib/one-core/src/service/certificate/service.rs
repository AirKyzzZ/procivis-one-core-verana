use ct_codecs::{Base64, Decoder};
use shared_types::CertificateId;

use super::CertificateService;
use super::dto::CertificateResponseDTO;
use super::error::CertificateServiceError;
use super::mapper::certificate_to_response_dto;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::identifier::IdentifierType;
use crate::validator::throw_if_org_id_not_matching_session;

impl CertificateService {
    pub async fn get_certificate(
        &self,
        id: CertificateId,
    ) -> Result<CertificateResponseDTO, CertificateServiceError> {
        let certificate = self
            .certificate_repository
            .get(id)
            .await
            .error_while("getting certificate")?
            .filter(|c| c.deleted_at.is_none())
            .ok_or(CertificateServiceError::NotFound(id))?;

        let org_id = certificate.organisation.as_ref().map(|o| o.id()).ok_or(
            CertificateServiceError::MappingError(format!(
                "missing organisation on certificate {}",
                certificate.id
            )),
        )?;

        throw_if_org_id_not_matching_session(&org_id, &*self.session_provider)
            .error_while("checking session")?;

        certificate_to_response_dto(certificate).await
    }

    pub async fn get_certificate_authority(
        &self,
        id: CertificateId,
    ) -> Result<Vec<u8>, CertificateServiceError> {
        let certificate = self
            .certificate_repository
            .get(id)
            .await
            .error_while("getting certificate")?
            .filter(|c| c.deleted_at.is_none())
            .ok_or(CertificateServiceError::NotFound(id))?;

        let identifier = self
            .identifier_repository
            .get(certificate.identifier_id, &Default::default())
            .await
            .error_while("getting identifier")?
            .ok_or(CertificateServiceError::MappingError(format!(
                "Identifier {} missing",
                certificate.identifier_id
            )))?;

        if identifier.r#type != IdentifierType::CertificateAuthority {
            tracing::info!("Invalid identifier type: {}", identifier.r#type);
            return Err(CertificateServiceError::NotFound(id));
        }

        let x5c = pem_chain_into_x5c(&certificate.chain).error_while("parsing PEM chain")?;

        let base64_encoded = x5c.first().ok_or(CertificateServiceError::MappingError(
            "Empty chain".to_string(),
        ))?;

        Base64::decode_to_vec(base64_encoded, None)
            .map_err(|e| CertificateServiceError::MappingError(e.to_string()))
    }
}
