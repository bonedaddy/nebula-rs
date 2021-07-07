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
    #[error("invalid x25519 private key banner")]
    InvalidX25519PrivateKeyBanner,
    #[error("invalid x25519 key length")]
    InvalidX25519KeyLength,
    #[error("invalid ed25519 private key banner")]
    InvalidED25519PrivateKeyBanner,
    #[error("invalid ed2519 key length")]
    InvalidED25519KeyLength,
    #[error("invalid x25519 public key banner")]
    InvalidX25519PublicKeyBanner,
    #[error("invalid ed25519 public key banner")]
    InvalidED25519PublicKeyBanner,
}