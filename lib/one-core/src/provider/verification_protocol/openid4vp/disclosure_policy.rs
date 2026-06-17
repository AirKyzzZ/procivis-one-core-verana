use asn1_rs::{Oid, oid};
use time::Duration;
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::Pem;
use x509_parser::x509::X509Name;

use crate::error::ContextWithErrorCode;
use crate::mapper::x509::CertificateParsingError;
use crate::proto::jwt::Jwt;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::signer::registration_certificate::model::Payload;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::util::access_cert_parser::etsi_access_cert_from_pem_chain;

pub(super) fn dn_matches_leaf_only(
    pem_chain: &str,
    dn: &str,
) -> Result<bool, VerificationProtocolError> {
    let chain = parse_pem_chain(pem_chain).error_while("parsing PEM chain")?;
    let leaf = chain.first().ok_or(VerificationProtocolError::Failed(
        "Empty cert chain".to_string(),
    ))?;
    let leaf = parse_cert(leaf).error_while("parsing cert")?;

    let dn = parse_dn(dn)?;
    Ok(dn_matches(leaf.subject(), &dn))
}

pub(super) fn dn_and_serial_matches_any_in_chain(
    pem_chain: &str,
    dn: &str,
    serial: &str,
) -> Result<bool, VerificationProtocolError> {
    let dn = parse_dn(dn)?;
    let serial = parse_serial(serial)?;

    let chain = parse_pem_chain(pem_chain).error_while("parsing PEM chain")?;
    for pem in chain {
        let cert = parse_cert(&pem).error_while("parsing cert")?;
        if serial != cert.raw_serial() {
            continue;
        }

        if dn_matches(cert.subject(), &dn) {
            return Ok(true);
        }
    }

    Ok(false)
}

pub(super) async fn entitlement_matches_reg_cert(
    entitlement: &str,
    reg_cert: &str,
) -> Result<bool, VerificationProtocolError> {
    let reg_cert = Jwt::<Payload>::build_from_token(reg_cert, None, None)
        .await
        .error_while("parsing JWT")?;

    for e in reg_cert.payload.custom.entitlements {
        if e.role.get_uri() == entitlement {
            return Ok(true);
        }
    }

    Ok(false)
}

pub(super) async fn entitlement_matches_via_registry(
    entitlement: &str,
    access_cert_pem_chain: &str,
    wrp_validator: &dyn WRPValidator,
) -> Result<bool, VerificationProtocolError> {
    let Ok(access_cert) = etsi_access_cert_from_pem_chain(access_cert_pem_chain) else {
        return Ok(false);
    };

    let Some(registry_url) = access_cert.registry_url else {
        return Ok(false);
    };

    let info = wrp_validator
        .fetch_from_registry(
            &access_cert.rp_id,
            &registry_url,
            None,
            Duration::seconds(0),
        )
        .await
        .error_while("fetching from WRP registry")?;

    Ok(info
        .payload
        .custom
        .data
        .entitlement
        .contains(&entitlement.to_string()))
}

fn parse_pem_chain(pem_chain: &str) -> Result<Vec<Pem>, CertificateParsingError> {
    Ok(Pem::iter_from_buffer(pem_chain.as_bytes()).collect::<Result<_, _>>()?)
}

fn parse_cert<'a>(pem: &'a Pem) -> Result<X509Certificate<'a>, CertificateParsingError> {
    Ok(pem.parse_x509()?)
}

fn parse_serial(serial: &str) -> Result<Vec<u8>, VerificationProtocolError> {
    let mut serial = serial.to_string();
    serial.retain(|c| c.is_ascii_hexdigit());
    hex::decode(serial).map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

struct DNEntry {
    oid: Oid<'static>,
    value: String,
}

const OID_ORG_ID: Oid<'static> = oid!(2.5.4.97);

fn parse_dn(dn: &str) -> Result<Vec<DNEntry>, VerificationProtocolError> {
    let mut result = vec![];

    let dn_iter = ldapdn::parse::dn_from_str(dn);
    for rdn in dn_iter {
        for atav in rdn.map_err(|e| VerificationProtocolError::Failed(e.to_string()))? {
            let (attr_type, attr_value) =
                atav.map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

            use x509_parser::oid_registry::*;

            let oid = match attr_type.to_uppercase().as_str() {
                // ISS-MDATA-EBD-4.2.5.2-07 Note 2
                "SN" | "SERIALNUMBER" => OID_X509_SERIALNUMBER,
                "ORGID" => OID_ORG_ID,

                "C" | "COUNTRYNAME" => OID_X509_COUNTRY_NAME,
                "O" | "ORGANIZATIONNAME" => OID_X509_ORGANIZATION_NAME,
                "CN" | "COMMONNAME" => OID_X509_COMMON_NAME,
                "SURNAME" => OID_X509_SURNAME,
                "GN" | "GIVENNAME" => OID_X509_GIVEN_NAME,
                _ => {
                    return Err(VerificationProtocolError::Failed(format!(
                        "Invalid DN attr: {attr_type}",
                    )));
                }
            };

            result.push(DNEntry {
                oid,
                value: attr_value.to_string(),
            });
        }
    }

    Ok(result)
}

fn dn_matches(subject: &X509Name<'_>, dn: &[DNEntry]) -> bool {
    for entry in dn {
        if !subject.iter_by_oid(&entry.oid).any(|attr| {
            attr.attr_value()
                .as_any_str()
                .is_ok_and(|value| value == entry.value)
        }) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const NATURAL_PERSON_ACCESS_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIDezCCAyCgAwIBAgIRAWV0XcoxzEf2lMeDlaZeFM4wCgYIKoZIzj0EAwIwEDEO
MAwGA1UEAwwFcGF2ZWwwHhcNMjYwNjE2MDcxODU5WhcNMzEwNjE1MDcxODU5WjCB
sDELMAkGA1UEBgwCQ1oxQzBBBgNVBFEMOmh0dHBzOi8vd2FsbGV0LXJlbHlpbmct
cGFydHktcmVnaXN0cnkuZGV2LnByb2NpdmlzLW9uZS5jb20xHTAbBgNVBAMMFFBh
dmVsIG5hdHVyYWwgcGVyc29uMRswGQYDVQQFDBJOVFJDWi1QYXZlbE5hdHVyYWwx
DjAMBgNVBCoMBVBhdmVsMRAwDgYDVQQEDAdaYXJlY2t5MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEkHjiAlxu9WQ4dy/K4nQmuhooiT2mf1VqzAyRKc8Jcfm551YA
lknyVsdgiDG59Kxb8NvqcmksA9iUE55mMYKIH6OCAbgwggG0MB8GA1UdIwQYMBaA
FLC2SiBtP6hMDNJgfL1aSokTFYScMB4GA1UdEQQXMBWGE2h0dHBzOi8vcHJvY2l2
aXMuY2gwDgYDVR0PAQH/BAQDAgOIMCUGA1UdJQQeMBwGCCsGAQUFBwMCBgcogYxd
BQEGBgcogbU0BAEGMG0GA1UdHwRmMGQwYqBgoF6GXGh0dHBzOi8vY29yZS5kZXYu
cHJvY2l2aXMtb25lLmNvbS9zc2kvcmV2b2NhdGlvbi92MS9jcmwvOTE3NDFhNTMt
MzY2ZC00NWEwLWI0MzQtMTM0YWYyNjI5MmMwMB0GA1UdDgQWBBQ7eDypu2QA1q+8
GLKMBz3bcwHSXzAPBgNVHRMBAf8EBTADAQEAMBQGA1UdIAQNMAswCQYHBACL7EAB
ADAaBgNVHRIEEzARhg9odHRwOi8vdGVzdC5jb20waQYIKwYBBQUHAQEEXTBbMFkG
CCsGAQUFBzAChk1odHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3Np
L2NhLzhjOGIwZTA0LTdhYjktNDQ0Ni05ZjA3LWMwODQ3MGY4ZjJjMTAKBggqhkjO
PQQDAgNJADBGAiEA2smtGWxjDjHXswYfsztWuf+mVjPfzPqqi9bwV1WAcSYCIQDO
UfLSewkUkc8ICKvRtaIDefxPXWJHHlW9nMwzTY2UcQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBpjCCAUygAwIBAgIUPMyEUIquDNc6CWl31oIpZIdoyVgwCgYIKoZIzj0EAwIw
EDEOMAwGA1UEAwwFcGF2ZWwwHhcNMjYwMzMwMTA0ODI2WhcNMjgwMzAzMTYwMDAw
WjAQMQ4wDAYDVQQDDAVwYXZlbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF6H
/Td+5BPAtNYWH/Bl3W97xHZy1g2GtjUtCEPmi0MD2Ax1WkWe6vSzqefYAbuts58e
Tg6l3f3CDFP32Nk2loWjgYMwgYAwHwYDVR0jBBgwFoAUsLZKIG0/qEwM0mB8vVpK
iRMVhJwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSwtkogbT+oTAzSYHy9WkqJ
ExWEnDASBgNVHRMBAf8ECDAGAQH/AgEAMBoGA1UdEgQTMBGGD2h0dHA6Ly90ZXN0
LmNvbTAKBggqhkjOPQQDAgNIADBFAiEAipy1JLdVrBngLEJbrgBa//xzaxgeq1JB
VXh+SVaLpfsCICrTtI8/vw+E12ZMSEjCpMOpvkxBVK0Uu/vBQlkZlspP
-----END CERTIFICATE-----
"#;

    const LEGAL_PERSON_ACCESS_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIDJzCCAtmgAwIBAgIRARBSoTMCkklvvRzn2SyFAAgwBQYDK2VwMBMxETAPBgNV
BAMMCHByb2NpdmlzMB4XDTI2MDQxMzE0MDMxNVoXDTI3MDQxMjE2MDAwMFowgYox
CzAJBgNVBAYMAkNaMUMwQQYDVQRRDDpodHRwczovL3dhbGxldC1yZWx5aW5nLXBh
cnR5LXJlZ2lzdHJ5LmRldi5wcm9jaXZpcy1vbmUuY29tMQ4wDAYDVQQDDAVQYXZl
bDEWMBQGA1UEYQwNTlRSQ1otUGF2ZWxJRDEOMAwGA1UECgwFUGF2ZWwwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASQeOICXG71ZDh3L8ridCa6GiiJPaZ/VWrMDJEp
zwlx+bnnVgCWSfJWx2CIMbn0rFvw2+pyaSwD2JQTnmYxgogfo4IBmTCCAZUwHwYD
VR0jBBgwFoAUIAZ96/jDMwwopccHJmzDE5r1I/YwGwYDVR0RBBQwEoYQaHR0cDov
L3BhdmVsLmNvbTAOBgNVHQ8BAf8EBAMCA4gwJQYDVR0lBB4wHAYIKwYBBQUHAwIG
ByiBjF0FAQYGByiBtTQEAQYwbQYDVR0fBGYwZDBioGCgXoZcaHR0cHM6Ly9jb3Jl
LmRldi5wcm9jaXZpcy1vbmUuY29tL3NzaS9yZXZvY2F0aW9uL3YxL2NybC8wZDVk
MWYzMy04M2FhLTQ1OGMtYjJjYy1hMmQ5NTJlYTJiYmMwHQYDVR0OBBYEFDt4PKm7
ZADWr7wYsowHPdtzAdJfMA8GA1UdEwEB/wQFMAMBAQAwFAYDVR0gBA0wCzAJBgcE
AIvsQAEBMGkGCCsGAQUFBwEBBF0wWzBZBggrBgEFBQcwAoZNaHR0cHM6Ly9jb3Jl
LmRldi5wcm9jaXZpcy1vbmUuY29tL3NzaS9jYS80ZWQxMjgwMi03ODIzLTRjY2Qt
OWNjZS0yMzQwNDYzNjVhNjQwBQYDK2VwA0EA5RWl3dOGtbqiJK5rrNwtMd/lb8WD
5IqBoRUI1VFUTSgMvFvS+NSVNHA3z+uuTlM+OJ9HrVV7AxhwcdbMtagcAA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBTjCCAQCgAwIBAgIUFhQN3wSL77lNydHbrEQ0nvAlVowwBQYDK2VwMBMxETAP
BgNVBAMMCHByb2NpdmlzMB4XDTI2MDMxMDA5MzAwOFoXDTMxMDMwOTA5MzAwOFow
EzERMA8GA1UEAwwIcHJvY2l2aXMwKjAFBgMrZXADIQC6tJ3YhFO4qaaAbrjfJ/bl
IMbdNvnRIJBKpQY4d5QPzqNmMGQwHwYDVR0jBBgwFoAUIAZ96/jDMwwopccHJmzD
E5r1I/YwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQgBn3r+MMzDCilxwcmbMMT
mvUj9jASBgNVHRMBAf8ECDAGAQH/AgEAMAUGAytlcANBAMVxsRaQIw8gVIWyAcBh
G+TtoOCpRpfedh4u41Bei9sSY74AZnnSRU56kYB09M5J05W7jWX0R7NIJEm1+T2n
WAg=
-----END CERTIFICATE-----
"#;

    #[test]
    fn test_dn_matching() {
        // matching complete set
        assert!(
            dn_matches_leaf_only(
                LEGAL_PERSON_ACCESS_CERTIFICATE,
                "C=CZ, CN=Pavel, ORGID=NTRCZ-PavelID, O=Pavel"
            )
            .unwrap()
        );
        assert!(dn_matches_leaf_only(NATURAL_PERSON_ACCESS_CERTIFICATE, "C=CZ, CN=Pavel natural person, serialNumber=NTRCZ-PavelNatural, givenName=Pavel, surname=Zarecky").unwrap());

        // matching subset
        assert!(dn_matches_leaf_only(LEGAL_PERSON_ACCESS_CERTIFICATE, "C=CZ").unwrap());
        assert!(
            dn_matches_leaf_only(LEGAL_PERSON_ACCESS_CERTIFICATE, "ORGID=NTRCZ-PavelID").unwrap()
        );
        assert!(dn_matches_leaf_only(LEGAL_PERSON_ACCESS_CERTIFICATE, "O=Pavel").unwrap());
        assert!(dn_matches_leaf_only(LEGAL_PERSON_ACCESS_CERTIFICATE, "CN=Pavel").unwrap());

        // dn matching parent CA
        assert!(!dn_matches_leaf_only(NATURAL_PERSON_ACCESS_CERTIFICATE, "CN=pavel").unwrap());
        assert!(!dn_matches_leaf_only(LEGAL_PERSON_ACCESS_CERTIFICATE, "CN=procivis").unwrap());
    }

    #[test]
    fn test_serial_matching() {
        // matching leaf
        assert!(
            dn_and_serial_matches_any_in_chain(
                LEGAL_PERSON_ACCESS_CERTIFICATE,
                "C=CZ, CN=Pavel, ORGID=NTRCZ-PavelID, O=Pavel",
                "01:10:52:a1:33:02:92:49:6f:bd:1c:e7:d9:2c:85:00:08",
            )
            .unwrap()
        );
        assert!(
            dn_and_serial_matches_any_in_chain(
                NATURAL_PERSON_ACCESS_CERTIFICATE,
                "C=CZ, CN=Pavel natural person, serialNumber=NTRCZ-PavelNatural, givenName=Pavel, surname=Zarecky",
                "01:65:74:5d:ca:31:cc:47:f6:94:c7:83:95:a6:5e:14:ce",
            )
            .unwrap()
        );

        // matching parent CA
        assert!(
            dn_and_serial_matches_any_in_chain(
                LEGAL_PERSON_ACCESS_CERTIFICATE,
                "CN=procivis",
                "16140ddf048befb94dc9d1dbac44349ef025568c",
            )
            .unwrap()
        );
        assert!(
            dn_and_serial_matches_any_in_chain(
                NATURAL_PERSON_ACCESS_CERTIFICATE,
                "CN=pavel",
                "3ccc84508aae0cd73a096977d68229648768c958",
            )
            .unwrap()
        );

        // wrong serial
        assert!(
            !dn_and_serial_matches_any_in_chain(
                LEGAL_PERSON_ACCESS_CERTIFICATE,
                "C=CZ",
                "01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01",
            )
            .unwrap()
        );
    }
}
