use thiserror::Error;

#[derive(Error, Debug)]
pub enum CertErrors {
    #[error("RawCertificate Details was empty")]
    RawCertDetailsEmpty,
    #[error("RawCertificate EncodedIps should be in pairs")]
    RawCertEncodedIpsNotPair,
    #[error("RawCertificate EncodedSubnets should be in pairs")]
    RawCertEncodedSubnetsNotPair,
    #[error("invalid nebula certificate banner")]
    InvalidCertBanner,
}