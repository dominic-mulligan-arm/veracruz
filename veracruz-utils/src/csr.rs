//! Certificate Singing Request generation
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::vec::Vec;

use ring::{ rand::SystemRandom, signature::{ EcdsaKeyPair, KeyPair } };
use err_derive::Error;

////////////////////////////////////////////////////////////////////////////////
// Error type.
////////////////////////////////////////////////////////////////////////////////

/// A generic catch-all error type for functionality related to policies.  This
/// error type contains more constructors when compiling for clients or hosts.
#[derive(Debug, Error)]
pub enum CertError {
    #[error(
        display = "CertError: Invalid: length for `{}`, expected {:?} but received {:?}.",
        variable,
        expected,
        received
    )]
    InvalidLength {
        variable: &'static str,
        expected: usize,
        received: usize,
    },
    #[error(
        display = "CertError: Invalid UTC Inputs: M:{}, D:{}, H:{}, min:{}, s:{}",
        month,
        day,
        hour,
        minute,
        second
    )]
    InvalidUtcInputs {
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    },
}

/// A struct to contain all of the information needed to generate a CSR (except
/// the signing key, of course)
pub struct CsrTemplate<'a> {
    /// The Template data to be filled with new values
    template: &'a[u8],
    /// The location of the public key in the `template` vec (start, end + 1)
    public_key_location: (usize, usize),
    /// The location of the signature in the `template` vec (start, end + 1)
    signature_location: (usize, usize),
    /// The location of the data that the signature will be generated over (start, end + 1)
    signature_range: (usize, usize),
    /// The location of the length field for the entire CSR (start, end + 1)
    overall_length_field_location: (usize, usize),
    /// The initial value of the length field for the entire CSR
    overall_length_initial_value: u16,
    /// The location of the length field for the signature in the `template vec (start, end + 1)
    signature_length_field_location: (usize, usize),
    /// The initial value of the length field of the signature
    signature_length_initial_value: u8,
}

/// A struct to contain all of the information needed to convert a CSR to a Cert
/// using a template
pub struct CertTemplate<'a> {
    /// The template data to be filled with new values
    template: &'a[u8],
    /// The location of the `notUntil` field in the `template` vec (start, end + 1)
    valid_from_location: (usize, usize),
    /// The location of the `notAfter` field in the `template` vec (start, end + 1)
    valid_until_location: (usize, usize),
    /// The location of the public key information in the template (start, end + 1)
    public_key_location: (usize, usize),
    /// The location of the signature in the `template` vec (start, end + 1)
    signature_location: (usize, usize),
    /// the location of the data that the signature will be generated over (start, end + 1)
    signature_range: (usize, usize),
    /// The location of the length field for the entire certificate (start, end + 1)
    overall_length_field_location: (usize, usize),
    /// The initial value of the length field for the entire certificate
    overall_length_initial_value: u16,
    /// The location of the length field for the signature in the `template` vec (start, end + 1)
    signature_length_field_location: (usize, usize),
    /// The initial value of the length field of the signature
    signature_length_initial_value: u8,
    /// The location of the enclave hash in the templates extension
    enclave_hash_location: (usize, usize)
}

/// The tempalate data needed to generate a Certificate Signing Request for the
/// root enclave
pub const ROOT_ENCLAVE_CSR_TEMPLATE: CsrTemplate = CsrTemplate {
    template: &[
        0x30, 0x81, 0xfd, 0x30, 0x81, 0xa5, 0x02, 0x01, 0x00, 0x30, 0x43, 0x31, 0x0b, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x08, 0x0c, 0x02, 0x54, 0x58, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08,
        0x56, 0x65, 0x72, 0x61, 0x63, 0x72, 0x75, 0x7a, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x0b, 0x52, 0x6f, 0x6f, 0x74, 0x45, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x30, 0x59,
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x53, 0x7e, 0x56, 0x17, 0xbf, 0x78, 0x91,
        0x2c, 0x68, 0x9c, 0x9b, 0xd1, 0x9b, 0x45, 0xa4, 0x2f, 0x39, 0x71, 0x02, 0x80, 0x7f, 0x19, 0x50,
        0x37, 0x69, 0x03, 0xd3, 0xe6, 0x1d, 0xf6, 0xc2, 0xa1, 0x2d, 0x8d, 0xd3, 0xdd, 0x17, 0xf0, 0xb6,
        0xcf, 0xf0, 0x6c, 0x06, 0x9a, 0x9f, 0xe0, 0x0d, 0xf9, 0x30, 0x5d, 0x72, 0xcd, 0xee, 0x69, 0x64,
        0x8e, 0xfd, 0x57, 0xda, 0x10, 0x21, 0x9d, 0x45, 0xc5, 0xa0, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x5a, 0x6a,
        0xd1, 0x7e, 0x5a, 0x1d, 0xdc, 0x98, 0x05, 0x32, 0x05, 0xf2, 0xaa, 0xfe, 0x89, 0x24, 0x7a, 0xa5,
        0xb0, 0x3c, 0xfc, 0xc4, 0xf8, 0xc3, 0xd6, 0x3f, 0x78, 0xea, 0x67, 0x0b, 0x97, 0x5a, 0x02, 0x20,
        0x03, 0xd1, 0x46, 0x8d, 0x34, 0xb4, 0xe1, 0xdc, 0x26, 0xef, 0x1b, 0x3a, 0x45, 0x2c, 0xbf, 0xb7,
        0x32, 0x66, 0x8b, 0xd5, 0x1a, 0xb3, 0x59, 0x6f, 0x08, 0xca, 0xc9, 0x18, 0xb7, 0x34, 0xa7, 0xbe
    ],
    public_key_location: (104, 104 + 65),
    signature_location: (186, 186 + 69),
    signature_range: (3, 171),
    overall_length_field_location: (2, 4),
    overall_length_initial_value: 185 - 2, //183-3,
    signature_length_field_location: (184, 185),
    signature_length_initial_value: 1,
};

pub const COMPUTE_ENCLAVE_CSR_TEMPLATE: CsrTemplate = CsrTemplate {
    template: &[0x30, 0x82, 0x01, 0x30, 0x30, 0x81, 0xd7, 0x02, 0x01, 0x00, 0x30, 0x75, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0c, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
    0x04, 0x07, 0x0c, 0x06, 0x41, 0x75, 0x73, 0x74, 0x69, 0x6e, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x08, 0x56, 0x65, 0x72, 0x61, 0x63, 0x72, 0x75, 0x7a, 0x31, 0x18, 0x30,
    0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0f, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x20,
    0x45, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0f, 0x56, 0x65, 0x72, 0x61, 0x63, 0x72, 0x75, 0x7a, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74,
    0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x50, 0x29, 0x2c, 0x67,
    0xbe, 0x19, 0x99, 0xed, 0xcc, 0xb0, 0x95, 0x06, 0x93, 0xea, 0xb8, 0xf1, 0xe9, 0xc5, 0x0c, 0x10,
    0xdd, 0x8c, 0x61, 0xa9, 0xa8, 0x3a, 0xe4, 0xb8, 0x17, 0xa7, 0xbe, 0xf6, 0xcb, 0x9f, 0x64, 0x76,
    0x57, 0x19, 0x3e, 0x84, 0x97, 0x66, 0x63, 0x8c, 0x26, 0x51, 0x71, 0x5c, 0x7d, 0x7f, 0xee, 0xe6,
    0x8a, 0xeb, 0xd4, 0xd1, 0x1d, 0x73, 0x5b, 0x94, 0xec, 0x9d, 0xf6, 0x98, 0xa0, 0x00, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02,
    0x20, 0x42, 0x24, 0x0e, 0x7d, 0x03, 0x71, 0x27, 0xbc, 0x5c, 0x6c, 0x81, 0xc3, 0xec, 0x2a, 0x75,
    0xb4, 0xaa, 0x46, 0xcd, 0x5c, 0x81, 0x2d, 0xdf, 0x05, 0x7c, 0xd5, 0x76, 0x8e, 0x03, 0xe2, 0xf5,
    0x54, 0x02, 0x21, 0x00, 0xf6, 0xfc, 0x0b, 0xb6, 0xd8, 0xbb, 0xc1, 0x11, 0x93, 0x47, 0x73, 0xbd,
    0xd9, 0xcf, 0x86, 0x14, 0x71, 0x15, 0x94, 0x6c, 0x5f, 0x35, 0xf1, 0x68, 0xfc, 0x24, 0xac, 0xbd,
    0xba, 0x07, 0xc2, 0x62, ],
    public_key_location: (155, 155 + 65),
    signature_location: (237, 237 + 71),
    signature_range: (4, 222),
    overall_length_field_location: (2, 4),
    overall_length_initial_value: 233,
    signature_length_field_location: (235, 236),
    signature_length_initial_value: 1,
};

pub const COMPUTE_ENCLAVE_CERT_TEMPLATE: CertTemplate = CertTemplate {
    template : &[
        0x30, 0x82, 0x01, 0xf1, 0x30, 0x82, 0x01, 0x97, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x17,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x43, 0x31, 0x0b,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x54, 0x58, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04,
        0x0a, 0x0c, 0x08, 0x56, 0x65, 0x72, 0x61, 0x63, 0x72, 0x75, 0x7a, 0x31, 0x14, 0x30, 0x12, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x52, 0x6f, 0x6f, 0x74, 0x45, 0x6e, 0x63, 0x6c, 0x61, 0x76,
        0x65, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x34, 0x32, 0x39, 0x32, 0x31, 0x33, 0x32, 0x31,
        0x32, 0x5a, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x34, 0x33, 0x30, 0x32, 0x31, 0x33, 0x32, 0x31, 0x32,
        0x5a, 0x30, 0x75, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
        0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73,
        0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x06, 0x41, 0x75, 0x73, 0x74, 0x69,
        0x6e, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x56, 0x65, 0x72, 0x61,
        0x63, 0x72, 0x75, 0x7a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0f, 0x43,
        0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x20, 0x45, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x56, 0x65, 0x72, 0x61, 0x63, 0x72, 0x75,
        0x7a, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04, 0xea, 0x6a, 0x79, 0x79, 0x29, 0xb8, 0xf3, 0xb4, 0xfe, 0xcc, 0x74, 0xed, 0x85,
        0x7d, 0xbd, 0x37, 0x53, 0x48, 0xf6, 0x9a, 0x52, 0x66, 0x2f, 0x39, 0xed, 0x03, 0xd8, 0xaa, 0x78,
        0xf0, 0x87, 0x97, 0x0e, 0x2a, 0x95, 0x1a, 0x83, 0x67, 0x00, 0xe7, 0xcf, 0x3c, 0x70, 0x6b, 0xb5,
        0x71, 0x90, 0xa5, 0xc3, 0xdc, 0x4c, 0x58, 0x4b, 0xd0, 0x6a, 0x5b, 0xb9, 0x07, 0x61, 0x9a, 0xd1,
        0xf6, 0x1a, 0x91, 0xa3, 0x4a, 0x30, 0x48, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x16,
        0x30, 0x14, 0x82, 0x12, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x45, 0x6e, 0x63, 0x6c, 0x61,
        0x76, 0x65, 0x2e, 0x64, 0x65, 0x76, 0x30, 0x27, 0x06, 0x03, 0x55, 0x1e, 0x01, 0x04, 0x20, 0xac,
        0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac,
        0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0xac, 0xab, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45,
        0x02, 0x21, 0x00, 0xa0, 0xe0, 0x27, 0xf7, 0x23, 0x13, 0x92, 0x7f, 0x2e, 0x74, 0xcb, 0xf4, 0xf2,
        0x57, 0x21, 0x1e, 0x53, 0x01, 0x63, 0xc0, 0xfc, 0xae, 0x44, 0x0c, 0x4f, 0x75, 0xf0, 0x1e, 0x00,
        0x8f, 0xdd, 0x26, 0x02, 0x20, 0x24, 0xb5, 0xa8, 0x7a, 0x70, 0x04, 0x04, 0x3f, 0xfc, 0x09, 0xca,
        0x04, 0x1d, 0xb5, 0x3b, 0x56, 0x89, 0x04, 0x7a, 0xda, 0x3e, 0x12, 0x50, 0x81, 0x2a, 0xa0, 0x3c,
        0x5e, 0x29, 0xb6, 0xbb, 0xd1
    ],
    valid_from_location: (101, 101 + 13),
    valid_until_location: (116, 116 + 13),
    public_key_location: ( 274, 274 + 65),
    signature_location: (430, 430 + 71),
    signature_range: (4, 415),
    overall_length_field_location: (2, 4),
    overall_length_initial_value: 430 - 4,
    signature_length_field_location: (428, 429),
    signature_length_initial_value: 1,
    enclave_hash_location: (383, 383 + 32),
};

const CSR_PUBKEY_LOCATION: (usize, usize) = (129 + 26, 220);

const CERTIFICATE_VALID_FROM: [u32; 6]= [2021, 5, 2, 17, 1, 0];
const CERTIFICATE_EXPIRY: [u32; 6] = [2021, 11, 29, 17, 1, 0];

pub fn generate_csr(template: &CsrTemplate, private_key: &EcdsaKeyPair) -> Result<Vec<u8>, CertError> {
    let public_key = private_key.public_key().as_ref().clone();
    let mut constructed_csr = template.template.to_vec();
    if public_key.len() != (template.public_key_location.1 - template.public_key_location.0) {
        return Err(CertError::InvalidLength { variable: "public_key", expected: template.public_key_location.1 - template.public_key_location.0, received: public_key.len() } );
    }
    constructed_csr.splice(
        template.public_key_location.0..template.public_key_location.1,
        public_key.iter().cloned(),
    );

    let rng = SystemRandom::new();
    let signature: Vec<u8> = private_key.sign(&rng, &constructed_csr[template.signature_range.0..template.signature_range.1]).unwrap().as_ref().to_vec();


    let signature_length = signature.len();
    constructed_csr.splice(
        template.signature_location.0..template.signature_location.1,
        signature,
    );

    let signature_field_length:u8 = (template.signature_length_initial_value + signature_length as u8) as u8;
    constructed_csr[template.signature_length_field_location.0] = signature_field_length;

    let overall_length:u16 = (template.overall_length_initial_value + signature_length as u16) as u16;
    if overall_length < 256 {
        constructed_csr[template.overall_length_field_location.0] = overall_length as u8;
    } else {
        constructed_csr[template.overall_length_field_location.0] = ((overall_length & 0xff00) >> 8) as u8;
        constructed_csr[template.overall_length_field_location.0 + 1] = (overall_length & 0xff) as u8;
    }

    return Ok(constructed_csr.clone());
}

pub fn convert_csr_to_cert(csr: &[u8], cert_template: &CertTemplate, enclave_hash: &[u8], private_key: &EcdsaKeyPair) -> Result<std::vec::Vec<u8>, CertError> {
    let mut constructed_cert = cert_template.template.to_vec();
    let valid_from = generate_utc_time(CERTIFICATE_VALID_FROM[0],
                                       CERTIFICATE_VALID_FROM[1],
                                       CERTIFICATE_VALID_FROM[2],
                                       CERTIFICATE_VALID_FROM[3],
                                       CERTIFICATE_VALID_FROM[4],
                                       CERTIFICATE_VALID_FROM[5])?;
    constructed_cert.splice(cert_template.valid_from_location.0..cert_template.valid_from_location.1,
        valid_from,
    );
    // TODO: Once the root enclave is gone, this can be done properly inside the proxy service
    let valid_until = generate_utc_time(CERTIFICATE_EXPIRY[0],
                                        CERTIFICATE_EXPIRY[1],
                                        CERTIFICATE_EXPIRY[2],
                                        CERTIFICATE_EXPIRY[3],
                                        CERTIFICATE_EXPIRY[4],
                                        CERTIFICATE_EXPIRY[5])?;
    constructed_cert.splice(cert_template.valid_until_location.0..cert_template.valid_until_location.1,
        valid_until,
    );

    // replace the public key in the template with the public key from the CSR
    let public_key = &csr[CSR_PUBKEY_LOCATION.0..CSR_PUBKEY_LOCATION.1];
    constructed_cert.splice(cert_template.public_key_location.0..cert_template.public_key_location.1, public_key.to_vec());

    // replace the dummy data in the template with the enclave hash
    constructed_cert.splice(cert_template.enclave_hash_location.0..cert_template.enclave_hash_location.1, enclave_hash.to_vec());

    // Sign the body of the constructed cert 
    let signature: Vec<u8> = private_key.sign(&SystemRandom::new(),
                                              &constructed_cert[cert_template.signature_range.0..cert_template.signature_range.1]).unwrap().as_ref().to_vec();
    // place the signature in the constructed_cert
    let signature_length = signature.len();
    constructed_cert.splice(
        cert_template.signature_location.0..cert_template.signature_location.1,
        signature,
    );

    let signature_field_length:u8 = (cert_template.signature_length_initial_value + signature_length as u8) as u8;
    constructed_cert[cert_template.signature_length_field_location.0] = signature_field_length;

    let overall_length:u16 = (cert_template.overall_length_initial_value + signature_length as u16) as u16;
    constructed_cert[cert_template.overall_length_field_location.0] = ((overall_length & 0xff00) >> 8) as u8;
    constructed_cert[cert_template.overall_length_field_location.0 + 1] = (overall_length & 0xff) as u8;

    return Ok(constructed_cert.clone());
}

pub fn generate_utc_time(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Result<Vec<u8>, CertError> {
    if month > 11 || day > 30 || hour > 23 || minute > 59 || second > 59 {
        return Err(CertError::InvalidUtcInputs { month,
                                                 day,
                                                 hour,
                                                 minute,
                                                 second,
        });
    }
    let year = year % 2000;
    let generated_time = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hour, minute, second
    );
    return Ok(generated_time.as_bytes().to_vec());
}