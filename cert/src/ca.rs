use std::{collections::HashMap, hash::Hash};
use std::sync::RwLock;
use crate::cert::{NebulaCertificate, unmarshal_nebula_certificate_from_pem};
use crate::errors::CertErrors;
use anyhow::Result;
use chrono::prelude::*;

#[derive(Debug)]
pub struct NebulaCAPool {
    pub cas: RwLock<HashMap<String, NebulaCertificate>>,
    pub cert_blocklist: RwLock<HashMap<String, bool>>,
}

impl NebulaCAPool {
    pub fn new() -> Self {
        Self{
            cas: RwLock::new(HashMap::new()),
            cert_blocklist: RwLock::new(HashMap::new()),
        }
    }
    /// verifies a nebula ca certificate and adds it to the pool
    /// only the first pem encoded object will be consumed
    pub fn add_ca_certificate(&mut self, pem_data: &[u8]) -> Result<()> {
        let cert = unmarshal_nebula_certificate_from_pem(pem_data)?;
        if !cert.details.is_ca {
            return Err(CertErrors::CertIsNotCaCert.into());
        }
        // make sure the ca cert was self signed
        let self_key = ed25519_dalek::PublicKey::from_bytes(cert.details.public_key.to_vec().as_slice())?;
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
    pub fn blacklist_fingerprint(&mut self, fingerprint: String) {
        self.cert_blocklist.write().unwrap().insert(fingerprint, true);
    }  
    pub fn reset_cert_blocklist(&mut self) {
        self.cert_blocklist.write().unwrap().clear();
    }
    pub fn is_blocklisted(&self, cert: &NebulaCertificate) -> Result<bool> {
        let sha256_sum = cert.sha256_sum()?;
        let result = self.cert_blocklist.read().unwrap().get(&sha256_sum);
        Ok(result == Some(&true))
        // let is_set = result.is_some();
        // Ok(is_set)
    }
}