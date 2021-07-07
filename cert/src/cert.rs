use std::net;
use std::time::SystemTime;
use bytes::Bytes;
use protobuf;
use crate::cert_pb::{self, RawNebulaCertificateDetails};
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


// todo(bonedaddy): this doesnt properly set teh ips, subnets, etc..
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

pub fn unmarshal_x25519_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let parsed_pem = pem::parse(data)?;
    if parsed_pem.tag != X25519_PRIVATE_KEY_BANNER {
        return Err(CertErrors::InvalidX25519PrivateKeyBanner.into());   
    }
    if parsed_pem.contents.len() != PUBLIC_KEY_LEN {
        return Err(CertErrors::InvalidX25519KeyLength.into());
    }
    Ok(parsed_pem.contents.to_vec())
}

pub fn marshal_ed25519_private_key(key: ed25519_dalek::SecretKey) -> String {
    pem::encode(&pem::Pem{
        tag: ED25519_PRIVATE_KEY_BANNER.to_string(),
        contents: Vec::from(key.to_bytes()),
    })
}

pub fn unmarshal_ed25519_private_key(data: &[u8]) -> Result<ed25519_dalek::SecretKey> {
    let parsed_pem = pem::parse(data)?;
    if parsed_pem.tag != ED25519_PRIVATE_KEY_BANNER {
        return Err(CertErrors::InvalidED25519PrivateKeyBanner.into());
    }
    if parsed_pem.contents.len() != PUBLIC_KEY_LEN {
        return Err(CertErrors::InvalidED25519KeyLength.into());
    }
    Ok(ed25519_dalek::SecretKey::from_bytes(parsed_pem.contents.as_slice())?)
}

pub fn marshal_x25519_public_key(data: &[u8]) -> String {
    pem::encode(&pem::Pem{
        tag: X25519_PUBLIC_KEY_BANNER.to_string(),
        contents: Vec::from(data)
    })
}

pub fn unmarshal_x25519_public_key(data: &[u8]) -> Result<Vec<u8>> {
    let parsed_pem = pem::parse(data)?;
    if parsed_pem.tag != X25519_PUBLIC_KEY_BANNER {
        return Err(CertErrors::InvalidX25519PublicKeyBanner.into());
    }
    if parsed_pem.contents.len() != PUBLIC_KEY_LEN {
        return Err(CertErrors::InvalidX25519KeyLength.into());
    }
    return Ok(parsed_pem.contents.to_vec())
}

pub fn marshal_ed25519_public_key(key: ed25519_dalek::PublicKey) -> String {
    pem::encode(&pem::Pem{
        tag: ED25519_PUBLIC_KEY_BANNER.to_string(),
        contents: Vec::from(key.to_bytes()),
    })
}

pub fn unmarshal_ed25519_public_key(data: &[u8]) -> Result<ed25519_dalek::PublicKey> {
    let parsed_pem = pem::parse(data)?;
    if parsed_pem.tag != ED25519_PUBLIC_KEY_BANNER {
        return Err(CertErrors::InvalidED25519PublicKeyBanner.into());
    }
    if parsed_pem.contents.len() != PUBLIC_KEY_LEN {
        return Err(CertErrors::InvalidED25519KeyLength.into());
    }
    Ok(ed25519_dalek::PublicKey::from_bytes(parsed_pem.contents.as_slice())?)
}

impl NebulaCertificate {
    pub fn get_raw_detals(&self) -> RawNebulaCertificateDetails {
        let mut raw_details = RawNebulaCertificateDetails::new();
        raw_details.Name = self.details.name.clone();
        raw_details.Groups = self.details.groups.clone().into();
        raw_details.NotBefore = self.details.not_before.timestamp();
        raw_details.NotAfter = self.details.not_after.timestamp();
        raw_details.PublicKey = self.details.public_key.to_vec();
        raw_details.IsCA = self.details.is_ca;

        for ip in self.details.ips.iter() {
            let ip = match *ip {
                net::IpAddr::V4(ipv4) => (
                    u32::from(ipv4)
                ),
                net::IpAddr::V6(ipv6) => {
                    println!("WARNING encountered ipv6 address");
                    let ipv6_as_v4 = ipv6.to_ipv4();
                    if ipv6_as_v4.is_none() {
                        println!("WARNING failed to convert ipv6 address to v4");
                        continue
                    }
                    let ipv6_as_v4 = ipv6_as_v4.unwrap();
                    u32::from(ipv6_as_v4)
                },
            };
            raw_details.Ips.push(ip);
        }

        for subnet in self.details.subnets.iter() {
            let subnet = match *subnet {
                net::IpAddr::V4(ipv4) => (
                    u32::from(ipv4)
                ),
                net::IpAddr::V6(ipv6) => {
                    println!("WARNING encountered ipv6 subnet");
                    let ipv6_as_v4 = ipv6.to_ipv4();
                    if ipv6_as_v4.is_none() {
                        println!("WARNING failed to convert ipv6 subnet to v4");
                        continue
                    }
                    let ipv6_as_v4 = ipv6_as_v4.unwrap();
                    u32::from(ipv6_as_v4)
                },
            };
            raw_details.Subnets.push(subnet);
        }

        raw_details.PublicKey = self.details.public_key.clone().to_vec();
        raw_details.Issuer = self.details.issuer.clone().as_bytes().to_vec();

        raw_details
    }
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
        println!("marshaled x25519 priv key {}", marshaled_priv_key);
    }
    #[test]
    pub fn test_marshal_ed25519_private_key() {
        let mut csprng = OsRng{};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let marshaled_ed25519 = marshal_ed25519_private_key(keypair.secret);
        println!("marshaled ed25519 priv key {}", marshaled_ed25519);
    }
    #[test]
    pub fn test_marshal_x25519_public_key() {
        let mut pub_key = String::new();
        pub_key.push_str("-----BEGIN NEBULA X25519 PUBLIC KEY-----");
        pub_key.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        pub_key.push_str("-----END NEBULA X25519 PUBLIC KEY-----");
        let marshaled = marshal_x25519_public_key(pub_key.as_bytes());
        println!("marshaled x25519 pub key {}", marshaled);
    }
    #[test]
    pub fn test_unmarshal_x25519_private_key() {
        let mut priv_key = String::new();
        priv_key.push_str("-----BEGIN NEBULA X25519 PRIVATE KEY-----");
        priv_key.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        priv_key.push_str("-----END NEBULA X25519 PRIVATE KEY-----");
        let err = unmarshal_x25519_private_key(priv_key.as_bytes());
        assert!(err.is_err() == false);
        let key_bytes = err.unwrap();
        let marshaled_priv_key = marshal_x25519_private_key(key_bytes.as_slice());
        println!("marhsaled unmarshaled x25519 priv key {}", marshaled_priv_key);
    }
    #[test]
    pub fn test_unmarshal_ed25519_private_key() {
        let mut csprng = OsRng{};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let marshaled_ed25519 = marshal_ed25519_private_key(keypair.secret);
        let unmarshaled_ed25519 = unmarshal_ed25519_private_key(marshaled_ed25519.as_bytes());
        assert!(unmarshaled_ed25519.is_err() == false);
        let unmarshaled_ed25519 = unmarshaled_ed25519.unwrap();
        let marshaled_ed25519_2 = marshal_ed25519_private_key(unmarshaled_ed25519);
        assert!(marshaled_ed25519 == marshaled_ed25519_2);
    }
    #[test]
    pub fn test_unmarshal_x25519_public_key() {
        let mut pub_key = String::new();
        pub_key.push_str("-----BEGIN NEBULA X25519 PUBLIC KEY-----");
        pub_key.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        pub_key.push_str("-----END NEBULA X25519 PUBLIC KEY-----");        
        let err = unmarshal_x25519_public_key(pub_key.as_bytes());
        assert!(err.is_err() == false);
        let unmarshaled_key_1 = err.unwrap();
        let marshaled_key = marshal_x25519_public_key(unmarshaled_key_1.clone().as_slice());
        let err = unmarshal_x25519_public_key(marshaled_key.as_bytes());
        assert!(err.is_err() == false);
        let unmarshaled_key_2 = err.unwrap();
        assert!(unmarshaled_key_1 == unmarshaled_key_2);
    }
    #[test]
    pub fn test_unmarshal_ed25519_public_key() {
        let mut csprng = OsRng{};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let marshaled_ed25519 = marshal_ed25519_public_key(keypair.public);
        let unmarshaled_ed25519_1 = unmarshal_ed25519_public_key(marshaled_ed25519.as_bytes());
        assert!(unmarshaled_ed25519_1.is_err() == false);
        let unmarshaled_ed25519_1 = unmarshaled_ed25519_1.unwrap();
        let marshaled_ed25519 = marshal_ed25519_public_key(unmarshaled_ed25519_1);
        let unmarshaled_ed25519_2 = unmarshal_ed25519_public_key(marshaled_ed25519.as_bytes());
        assert!(unmarshaled_ed25519_2.is_err() == false);
        let unmarshaled_ed25519_2 = unmarshaled_ed25519_2.unwrap();
        let a = unmarshaled_ed25519_1.as_bytes();
        let b = unmarshaled_ed25519_2.as_bytes();
        assert!(a == b);
    }
}