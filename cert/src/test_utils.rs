use crate::cert::NebulaCertificate;
use anyhow::Result;
use chrono::prelude::*;
use chrono::NaiveDate;
use chrono::NaiveDateTime;
use rand::rngs::OsRng;
use std::net;
use std::net::IpAddr;

use bytes::Bytes;
use ed25519_dalek::Keypair as ED25519_Keypair;
use x25519_dalek::{
    PublicKey as X25519_PublicKey, StaticSecret as X25519_StaticSecret,
};

#[allow(dead_code)]
pub fn new_test_cert(
    ca: &NebulaCertificate,
    // this should the ca private key
    ca_signer_key: &ED25519_Keypair,
    before: NaiveDateTime,
    after: NaiveDateTime,
    ips: Vec<IpAddr>,
    subnets: Vec<IpAddr>,
    groups: Vec<String>,
) -> Result<(
    NebulaCertificate,
    X25519_PublicKey,
    X25519_StaticSecret,
    ED25519_Keypair,
)> {
    let issuer = ca.sha256_sum()?;
    let mut nebula_cert = NebulaCertificate::default();
    nebula_cert.details.name = "testing".to_string();
    nebula_cert.details.ips = ips;
    nebula_cert.details.subnets = subnets;
    nebula_cert.details.not_before = before;
    nebula_cert.details.not_after = after;
    nebula_cert.details.groups = groups;
    nebula_cert.details.issuer = issuer;
    let mut csprng = OsRng {};
    let keypair = ED25519_Keypair::generate(&mut csprng);
    let x25519_secret =
        crypto_utils::ed25519_secret_to_x25519_secret_static(keypair.secret.to_bytes());
    let x25519_public = X25519_PublicKey::from(&x25519_secret);
    nebula_cert.details.public_key = Bytes::from(keypair.public.to_bytes().to_vec());
    nebula_cert.sign(ca_signer_key)?;
    /*
    key []byte, before, after time.Time, ips, subnets []*net.IPNet, groups []string
    */

    Ok((nebula_cert, x25519_public, x25519_secret, keypair))
}

#[allow(dead_code)]
pub fn new_test_ca_cert(
    before: NaiveDateTime,
    after: NaiveDateTime,
    ips: Vec<IpAddr>,
    subnets: Vec<IpAddr>,
    groups: Vec<String>,
) -> Result<(NebulaCertificate, ED25519_Keypair)> {
    let mut csprng = OsRng {};
    let keypair = ED25519_Keypair::generate(&mut csprng);
    let mut nebula_cert = NebulaCertificate::default();
    nebula_cert.details.name = "test ca".to_string();
    nebula_cert.details.not_before = before;
    nebula_cert.details.not_after = after;
    nebula_cert.details.public_key = Bytes::from(keypair.public.to_bytes().to_vec());
    nebula_cert.details.is_ca = true;
    nebula_cert.details.ips = ips;
    nebula_cert.details.subnets = subnets;
    nebula_cert.details.groups = groups;
    nebula_cert.sign(&keypair)?;
    Ok((nebula_cert, keypair))
}

#[allow(dead_code)]
pub fn create_test_ca_cert() -> Result<(NebulaCertificate, ED25519_Keypair)> {
    new_test_ca_cert(
        Utc::now().naive_local(),
        NaiveDate::from_ymd(2029, 01, 01).and_hms(0, 0, 0),
        Vec::from([
            net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 1)),
            net::IpAddr::V4(net::Ipv4Addr::new(192, 168, 0, 1)),
        ]),
        Vec::from([
            net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 250, 0)),
            net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 251, 0)),
        ]),
        Vec::from(["group1".to_string(), "group2".to_string()]),
    )
}

#[allow(dead_code)]
pub fn create_test_ca_cert_client_cert() -> Result<(
    NebulaCertificate,
    X25519_PublicKey,
    X25519_StaticSecret,
    ED25519_Keypair,
    NebulaCertificate,
    ED25519_Keypair,
)> {
    let (ca_cert, ca_keypair) = create_test_ca_cert()?;
    let (cert, cert_x25519_public_key, cert_x25519_secret_key, cert_ed25519_keypair) =
        new_test_cert(
            &ca_cert,
            &ca_keypair,
            Utc::now().naive_local(),
            NaiveDate::from_ymd(2028, 12, 01).and_hms(0, 0, 0),
            Vec::from([
                net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 2)),
                net::IpAddr::V4(net::Ipv4Addr::new(192, 168, 0, 2)),
            ]),
            Vec::from([
                net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 250, 0)),
                net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 251, 0)),
            ]),
            Vec::from(["group1".to_string(), "group2".to_string()]),
        )?;
    Ok((
        cert,
        cert_x25519_public_key,
        cert_x25519_secret_key,
        cert_ed25519_keypair,
        ca_cert,
        ca_keypair,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::naive::{NaiveDate, NaiveDateTime};
    use chrono::prelude::*;
    use std::net;
    #[test]
    pub fn test_new_ca_cert() {
        let result = create_test_ca_cert();
        assert!(result.is_err() == false);
    }
    #[test]
    pub fn test_new_cert() {
        let (ca_cert, ca_keypair) = create_test_ca_cert().unwrap();
        let res = new_test_cert(
            &ca_cert,
            &ca_keypair,
            Utc::now().naive_local(),
            NaiveDate::from_ymd(2028, 12, 01).and_hms(0, 0, 0),
            Vec::from([
                net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 2)),
                net::IpAddr::V4(net::Ipv4Addr::new(192, 168, 0, 2)),
            ]),
            Vec::from([
                net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 250, 0)),
                net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 251, 0)),
            ]),
            Vec::from(["group1".to_string(), "group2".to_string()]),
        );
        assert!(res.is_err() == false);
    }
    #[test]
    pub fn test_create_test_ca_cert_client_cert() {
        let res = create_test_ca_cert_client_cert();
        assert!(res.is_err() == false);
    }
}
