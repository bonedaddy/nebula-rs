use std::net;
use std::time::SystemTime;
use bytes::Bytes;
use protobuf;
use crate::cert_pb;
use anyhow::Result;
use protobuf::Message;
use crate::errors::CertErrors;
use chrono::NaiveDateTime;
use std::iter::FromIterator;
use pem;
use ed25519_dalek;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const CERT_BANNER: &str = "NEBULA CERTIFICATE";
pub const X25519_PRIVATE_KEY_BANNER: &str = "NEBULA X25519 PRIVATE KEY";
pub const X25519_PUBLIC_KEY_BANNER: &str = "NEBULA X25519 PUBLIC KEY";
pub const ED25519_PRIVATE_KEY_BANNER: &str = "NEBULA ED25519 PRIVATE KEY";
pub const ED25519_PUBLIC_KEY_BANNER: &str = "NEBULA ED25519 PUBLIC KEY";


#[derive(Debug, Clone)]
pub struct NebulaCertificate{
    pub details: NebulaCertificateDetails,
    pub signature: Bytes,
}

#[derive(Debug, Clone)]
pub struct NebulaCertificateDetails{
    pub name: String,
    pub ips: Vec<net::IpAddr>,
    pub subnets: Vec<net::IpAddr>,
    pub groups: Vec<String>,
    pub not_before: NaiveDateTime,
    pub not_after: NaiveDateTime,
    // pub public_key: Vec<u8>,
    pub public_key: Bytes,
    pub is_ca: bool,
    pub issuer: String,
}


pub fn unmarshal_nebula_certificate(data: &[u8]) -> Result<NebulaCertificate> {

    let raw_cert = cert_pb::RawNebulaCertificate::parse_from_bytes(data)?;

    if raw_cert.Details.is_none() {
        return Err(CertErrors::RawCertDetailsEmpty.into());
    }
    let mut details = raw_cert.Details.unwrap();
    if details.Ips.len() % 2 != 0 {
        return Err(CertErrors::RawCertEncodedIpsNotPair.into());
    }
    if details.Subnets.len() % 2 != 0 {
        return Err(CertErrors::RawCertEncodedSubnetsNotPair.into());
    }
    let mut groups: Vec<String> = details.clone().take_Groups().into();
    let mut nebula_certificate = NebulaCertificate{
        details: NebulaCertificateDetails{
            name: "".to_string(),
            ips: Vec::with_capacity(details.Ips.len()/2),
            subnets: Vec::with_capacity(details.Subnets.len()/2),
            groups: Vec::new(),
            not_before: NaiveDateTime::from_timestamp(details.NotBefore, 0),
            not_after: NaiveDateTime::from_timestamp(details.NotAfter, 0),
            public_key: details.PublicKey.into(),
            is_ca: details.IsCA,
            // todo(bonedaddy): add inverted groups
            issuer: "".to_string(),
        },
        signature: raw_cert.Signature.into(),
    };

    nebula_certificate.details.name = std::mem::take(&mut details.Name);
    nebula_certificate.details.groups = std::mem::take(&mut groups);
    // todo(bonedaddy): this needs to be hex encoded
    // nebula_certificate.details.issuer = std::mem::take(&mut details.Issuer);
    Ok(nebula_certificate)
}


pub fn unmarshal_nebula_certificate_from_pem(pem_data: &[u8]) -> Result<NebulaCertificate> {
    let parsed_pem = pem::parse(pem_data)?;
    if parsed_pem.tag != CERT_BANNER {
        return Err(CertErrors::InvalidCertBanner.into());
    }
    unmarshal_nebula_certificate(&parsed_pem.contents[..])
}


pub fn marshal_x25519_private_key(data: &[u8]) -> String {
    pem::encode(&pem::Pem{
        tag: X25519_PRIVATE_KEY_BANNER.to_string(),
        contents: Vec::from(data),
    })
}


pub fn marshal_ed25519_private_key(key: ed25519_dalek::SecretKey) -> String {
    pem::encode(&pem::Pem{
        tag: ED25519_PRIVATE_KEY_BANNER.to_string(),
        contents: Vec::from(key.to_bytes()),
    })
}


#[cfg(test)]
mod tests {
    // from https://github.com/slackhq/nebula/blob/master/cert/cert_test.go
    use super::*;
    use chrono::prelude::*;
    
    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;
    use ed25519_dalek::Signature;
    #[test]
    pub fn test_unmarshal_nebula_certificate() {
        let mut raw_cert = cert_pb::RawNebulaCertificate::new();
        let mut raw_cert_details = cert_pb::RawNebulaCertificateDetails::new();
        let home_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
        let home_ip_ext = std::net::Ipv4Addr::new(192, 168, 0, 1);
        let home_ip_subnet = std::net::Ipv4Addr::new(255, 250,0,0);
        let home_ip_ext_subnet = std::net::Ipv4Addr::new(255,254,0,0);
        
        raw_cert_details.set_Name("TestCertificate".to_string());
        raw_cert_details.set_Ips(Vec::from([u32::from(home_ip), u32::from(home_ip_ext)]));
        raw_cert_details.set_Subnets(Vec::from([u32::from(home_ip_subnet), u32::from(home_ip_ext_subnet)]));
        raw_cert_details.set_NotBefore(Utc::now().timestamp());
        raw_cert_details.set_NotAfter(Utc::now().timestamp());
        raw_cert_details.set_PublicKey(Vec::from([0, 1, 2, 3, 4]));
        raw_cert.set_Details(raw_cert_details);

        let raw_cert_bytes = raw_cert.write_to_bytes().expect("failed to marshal raw cert");

        let certificate = unmarshal_nebula_certificate(&raw_cert_bytes[..]).expect("failed to unmarshal certificate");
        assert!(certificate.details.name == "TestCertificate".to_string());
    }
    #[test]
    pub fn test_unmarshal_nebula_certificate_from_pem() {
        let mut pub_key = String::new();
        pub_key.push_str("-----BEGIN NEBULA CERTIFICATE-----");
        pub_key.push_str("CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL");
        pub_key.push_str("vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv");
        pub_key.push_str("bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB");
        pub_key.push_str("-----END NEBULA CERTIFICATE-----");
        let cert = unmarshal_nebula_certificate_from_pem(pub_key.as_bytes());
        assert!(cert.is_err() == false);
        let cert = cert.unwrap();
        println!("cert {:#?}", cert);
    }
    #[test]
    pub fn test_marshal_x25519_private_key() {
        let mut priv_key = String::new();
        priv_key.push_str("-----BEGIN NEBULA X25519 PRIVATE KEY-----");
        priv_key.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        priv_key.push_str("-----END NEBULA X25519 PRIVATE KEY-----");
        let marshaled_priv_key = marshal_x25519_private_key(priv_key.as_bytes());
        println!("marshaled: {}", marshaled_priv_key);
    }
    #[test]
    pub fn test_marshal_ed25519_private_key() {
        let mut csprng = OsRng{};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let marshaled_ed25519 = marshal_ed25519_private_key(keypair.secret);
        println!("marshaled: {}", marshaled_ed25519);
    }
}