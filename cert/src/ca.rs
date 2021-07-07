use crate::cert::{unmarshal_nebula_certificate_from_pem, NebulaCertificate};
use crate::errors::CertErrors;
use anyhow::Result;
use chrono::prelude::*;
use std::sync::RwLock;
use std::{collections::HashMap};

#[derive(Debug)]
pub struct NebulaCAPool {
    pub cas: RwLock<HashMap<String, NebulaCertificate>>,
    pub cert_blocklist: RwLock<HashMap<String, bool>>,
}

impl NebulaCAPool {
    pub fn new() -> Self {
        Self {
            cas: RwLock::new(HashMap::new()),
            cert_blocklist: RwLock::new(HashMap::new()),
        }
    }
    // todo(bonedaddy): fully implement
    // https://github.com/slackhq/nebula/blob/master/cert/ca.go#L24
    pub fn new_from_bytes(ca_pems: &[u8]) -> Result<Self> {
        let mut ca_pool = Self::new();
        ca_pool.add_ca_certificate(ca_pems)?;
        Ok(ca_pool)
    }
    /// verifies a nebula ca certificate and adds it to the pool
    /// only the first pem encoded object will be consumed
    pub fn add_ca_certificate(&mut self, pem_data: &[u8]) -> Result<()> {
        let cert = unmarshal_nebula_certificate_from_pem(pem_data)?;
        if !cert.details.is_ca {
            return Err(CertErrors::CertIsNotCaCert.into());
        }
        // make sure the ca cert was self signed
        let self_key =
            ed25519_dalek::PublicKey::from_bytes(cert.details.public_key.to_vec().as_slice())?;
        let check = cert.check_signature(self_key);
        if check.is_err() {
            return Err(CertErrors::CertIsNotSelfSigned.into());
        }
        // make sure the ca cert is not expired
        if cert.expired(Utc::now().naive_local()) {
            return Err(CertErrors::CertIsExpired.into());
        }
        let sha256_sum = cert.sha256_sum()?;
        // todo(bonedaddy): this will panic if lock is pisoned
        self.cas.write().unwrap().insert(sha256_sum, cert);
        Ok(())
    }
    pub fn blocklist_cert(&mut self, cert: &NebulaCertificate) -> Result<()> {
        let fingerprint = cert.sha256_sum()?;
        self.blocklist_fingerprint(fingerprint);
        Ok(())
    }
    pub fn blocklist_fingerprint(&mut self, fingerprint: String) {
        self.cert_blocklist
            .write()
            .unwrap()
            .insert(fingerprint, true);
    }
    pub fn reset_cert_blocklist(&mut self) {
        self.cert_blocklist.write().unwrap().clear();
    }
    pub fn is_blocklisted(&self, cert: &NebulaCertificate) -> Result<bool> {
        let sha256_sum = cert.sha256_sum()?;
        let read = self.cert_blocklist.read().unwrap();
        let result = read.get(&sha256_sum);
        Ok(result == Some(&true))
    }
    /// attempts to return the signing certificate for the provider certificate
    /// doesnt perform signature validation
    pub fn get_ca_for_cert(&self, cert: &NebulaCertificate) -> Result<NebulaCertificate> {
        if cert.details.issuer == "" {
            return Err(CertErrors::NoCertIssuer.into());
        }
        let read = self.cas.read().unwrap();
        let signer = read.get(&cert.details.issuer);
        if signer.is_none() {
            return Err(CertErrors::NoCaIssuer.into());
        }
        Ok(signer.unwrap().clone())
    }
    /// returns an array of trusted CA fingerprints
    pub fn get_fingerprints(&self) -> Vec<String> {
        let read = self.cas.read().unwrap();
        let mut fingerprints = Vec::with_capacity(read.len());
        for (key, _val) in read.iter() {
            fingerprints.push(key.clone());
        }
        fingerprints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils;
    #[test]
    pub fn test_new_capool() {
        NebulaCAPool::new();
    }
    #[test]
    pub fn test_ca_pool_e2e() {
        let res = test_utils::create_test_ca_cert_client_cert();
        assert!(res.is_err() == false);
        let (
            client_cert,
            client_cert_x25519_public_key,
            client_cert_x25519_secret_key,
            client_cert_ed25519_keypair,
            ca_cert,
            ca_keypair,
        ) = res.unwrap();
        let mut ca_pool =
            NebulaCAPool::new_from_bytes(ca_cert.marshal_to_pem().unwrap().as_bytes()).unwrap();
        ca_pool.blocklist_cert(&ca_cert).unwrap();
        assert!(ca_pool.is_blocklisted(&ca_cert).unwrap() == true);
        ca_pool.reset_cert_blocklist();
        assert!(ca_pool.is_blocklisted(&ca_cert).unwrap() == false);

        let client_ca_cert = ca_pool.get_ca_for_cert(&client_cert);
        if client_ca_cert.is_err() {
            println!("client_ca_cert err {:#?}", client_ca_cert.err());
            assert!(true == false);
            return;
        }
        let ca_cert_sha256_sum = ca_cert.sha256_sum().unwrap();
        let client_ca_cert = client_ca_cert.unwrap();
        let client_ca_cert_sha256_sum = client_ca_cert.sha256_sum().unwrap();
        assert!(ca_cert_sha256_sum == client_ca_cert_sha256_sum);
        let fingerprints = ca_pool.get_fingerprints();
        assert!(fingerprints.len() == 1);
        assert!(fingerprints[0] == ca_cert_sha256_sum);
    }
}
