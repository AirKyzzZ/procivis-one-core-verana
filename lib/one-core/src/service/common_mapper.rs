use ct_codecs::{Base64, Decoder};

use crate::model::list_filter::ListFilterCondition;
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::trust_information::TrustDetails;
use crate::provider::signer::registration_certificate::model::Payload;
use crate::service::common_dto::{
    BoundedB64Image, EudiIntermediaryResponseDTO, EudiTrustInformationResponseDTO, ListQueryDTO,
    TrustInformationResponseDTO,
};
use crate::service::error::{ServiceError, ValidationError};
use crate::util::access_cert_parser::EtsiParsedAccessCert;

impl<const MAX: usize> TryFrom<String> for BoundedB64Image<MAX> {
    type Error = ValidationError;

    fn try_from(img: String) -> Result<Self, Self::Error> {
        let mut splits = img.splitn(2, ',');
        match splits.next() {
            Some("data:image/png;base64") | Some("data:image/jpeg;base64") => {}
            Some(data) => {
                return Err(ValidationError::InvalidImage(format!(
                    "Invalid mime type: {data}"
                )));
            }
            None => {
                return Err(ValidationError::InvalidImage(
                    "Missing mime type".to_owned(),
                ));
            }
        };
        let Some(base64) = splits.next() else {
            return Err(ValidationError::InvalidImage(
                "Missing base64 data".to_string(),
            ));
        };
        let mut buf = vec![0; MAX];
        // Decode will fail if data is longer than `buf` (`MAX` bytes)
        Base64::decode(buf.as_mut_slice(), base64, None).map_err(|err| {
            ValidationError::InvalidImage(format!("Failed to decode base64 data: {err}"))
        })?;
        Ok(BoundedB64Image(img))
    }
}
impl<const MAX: usize> From<BoundedB64Image<MAX>> for String {
    fn from(value: BoundedB64Image<MAX>) -> Self {
        value.0
    }
}

impl<Sorting, FilterDTO, Filter, Include> From<ListQueryDTO<Sorting, FilterDTO, Include>>
    for ListQuery<Sorting, Filter, Include>
where
    FilterDTO: Into<ListFilterCondition<Filter>>,
{
    fn from(value: ListQueryDTO<Sorting, FilterDTO, Include>) -> Self {
        Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size,
            }),
            sorting: value.sort.map(|column| ListSorting {
                column,
                direction: value.sort_direction,
            }),
            filtering: Some(value.filter.into()),
            include: value.include,
        }
    }
}

impl TryFrom<TrustDetails> for TrustInformationResponseDTO {
    type Error = ServiceError;

    fn try_from(value: TrustDetails) -> Result<Self, Self::Error> {
        let response = match value {
            TrustDetails::Etsi {
                access_certificate,
                registration_certificate,
            } => {
                let (intermediary, email, phone) =
                    map_access_cert(access_certificate, &registration_certificate);
                TrustInformationResponseDTO {
                    eudi_ecosystem: Some(EudiTrustInformationResponseDTO {
                        name: registration_certificate.custom.name,
                        website: registration_certificate.custom.support_uri,
                        email,
                        phone,
                        country: registration_certificate.custom.country,
                        identifier: registration_certificate.subject.ok_or(
                            ServiceError::MappingError(
                                "Missing registration certificate subject".to_string(),
                            ),
                        )?,
                        service_description: registration_certificate
                            .custom
                            .service_descriptions
                            .into_iter()
                            .map(|langs| {
                                langs
                                    .into_iter()
                                    .map(|lang| (lang.lang, lang.value))
                                    .collect()
                            })
                            .collect(),
                        supervisory_authority: registration_certificate
                            .custom
                            .supervisory_authority,
                        intermediary,
                        is_public_sector: registration_certificate
                            .custom
                            .public_body
                            .unwrap_or_default(),
                    }),
                }
            }
        };
        Ok(response)
    }
}

fn map_access_cert(
    access_certificate: EtsiParsedAccessCert,
    registration_certificate: &JWTPayload<Payload>,
) -> (
    Option<EudiIntermediaryResponseDTO>,
    Option<String>,
    Option<String>,
) {
    if registration_certificate.custom.intermediary.is_some() {
        (
            Some(EudiIntermediaryResponseDTO {
                name: access_certificate.common_name,
                identifier: access_certificate.rp_id,
                website: access_certificate.support_uri.clone(),
                email: access_certificate.email,
                phone: access_certificate.phone,
                country: access_certificate.country,
            }),
            None,
            None,
        )
    } else {
        (None, access_certificate.email, access_certificate.phone)
    }
}

#[cfg(test)]
mod test {
    use ct_codecs::{Base64, Encoder};

    use super::BoundedB64Image;
    use crate::service::error::ValidationError;

    #[test]
    fn test_bounded_base64_image() {
        let data = vec![0; 10];
        let data_str = format!(
            "data:image/png;base64,{}",
            Base64::encode_to_string(&data).unwrap()
        );
        let result = BoundedB64Image::<10>::try_from(data_str.clone());
        assert!(result.is_ok());

        let result = BoundedB64Image::<9>::try_from(data_str);
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));

        let result =
            BoundedB64Image::<10>::try_from("data:image/png;base64,NÖT_BÄSE64".to_string());
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));

        let result = BoundedB64Image::<10>::try_from(format!(
            "data:image/gif;base64,{}", // unsupported mime type
            Base64::encode_to_string(&data).unwrap()
        ));
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));
    }
}
