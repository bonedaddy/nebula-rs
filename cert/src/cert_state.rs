use crate::cert::NebulaCertificate;
use anyhow::Result;
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq, Clone)]
pub struct CertStateInner<'a> {
    pub certificate: &'a NebulaCertificate,
    pub raw_certificate: Vec<u8>,
    pub raw_certificate_no_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub struct CertState<'a> {
    pub inner: Arc<RwLock<CertStateInner<'a>>>,
}

impl<'a> CertState<'a> {
    pub fn new(
        certificate: &'a mut NebulaCertificate,
        private_key: Vec<u8>,
    ) -> Result<Self> {
        let raw_certificate = certificate.marshal()?;
        // take the public key
        let public_key = std::mem::take(&mut certificate.details.public_key);
        let raw_cert_no_key = certificate.marshal()?;
        // put back
        let _ = std::mem::replace(&mut certificate.details.public_key, public_key);
        let inner = Arc::new(
            RwLock::new(
                CertStateInner{
                    raw_certificate,
                    certificate,
                    private_key,
                    public_key: certificate.details.public_key.clone().to_vec(),
                    raw_certificate_no_key: raw_cert_no_key,
                }
            )
        );
        let cert_state = Self{
            inner,
        };
        Ok(cert_state)
    }
}

#[cfg(test)]
mod test {
    use crate::{cert, test_utils};

    use super::*;
    #[test]
    fn test_cert_state() {
        let (
            mut cert,
            _cert_x25519_public_key,
            _cert_x25519_secret_key,
            cert_ed25519_keypair,
            _ca_cert,
            _ca_keypair,
        ) = test_utils::create_test_ca_cert_client_cert().unwrap();
        let cert_state = CertState::new(
            &mut cert,
            cert_ed25519_keypair.secret.to_bytes().to_vec(),
        ).unwrap();
        let cert_2 = cert::unmarshal_nebula_certificate(
            &cert_state.inner.read().unwrap().raw_certificate_no_key[..]
        ).unwrap();
        // ensure the certificate doesnt contain a key
        assert!(cert_2.details.public_key.len() == 0);
    }
}