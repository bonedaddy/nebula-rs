pub fn edwards_to_montgomery(cepk: [u8; 32]) -> Option<[u8; 32]> {
    // https://github.com/dalek-cryptography/ed25519-dalek/issues/118#issuecomment-590060371
    let epk = ::curve25519_dalek::edwards::CompressedEdwardsY(cepk).decompress()?;
    if epk.is_small_order() {
        return None;
    }
    let montgomery_bytes = epk.to_montgomery().to_bytes();
    // Or maybe you prefer: if epk.is_identity() { return EdwardsPoint::identity(); }
    Some(montgomery_bytes)
    // Or return the curve25519_dalek::MontgomeryPoint if you prefer.
}

pub fn ed25519_secret_to_x25519_secret_static(key_bytes: [u8; 32]) -> x25519_dalek::StaticSecret {
    x25519_dalek::StaticSecret::from(key_bytes)
}

pub fn ed25519_public_to_x25519_public(key_bytes: [u8; 32]) -> Option<x25519_dalek::PublicKey> {
    let mut bits: [u8; 32] = [0; 32];
    bits.copy_from_slice(&key_bytes[..]);
    let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bits);
    let point = compressed.decompress()?;
    let m_point = point.to_montgomery();
    Some(x25519_dalek::PublicKey::from(m_point.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use x25519_dalek;
    use rand::rngs::OsRng;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    fn conv_test() {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        let private_key = keypair.secret;
        let public_key = keypair.public;
        let dh_private_key = ed25519_secret_to_x25519_secret_static(private_key.to_bytes());
        let dh_public_key = ed25519_public_to_x25519_public(public_key.to_bytes()).unwrap();
        dh_private_key.diffie_hellman(&dh_public_key);
    }
}
