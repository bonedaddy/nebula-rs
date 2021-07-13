use noise::cipher_state;
use snow::{HandshakeState, params::{HandshakePattern, NoiseParams}, Builder};
use cert::cert_state::CertState;
use cert::cert::NebulaCertificate;
use bytes::Bytes;
use anyhow::Result;
use ed25519_dalek::Keypair as ED25519_Keypair;

pub struct ConnectionState<'a> {
    pub e_key: Option<&'a cipher_state::CipherState<'a>>,
    pub d_key: Option<&'a cipher_state::CipherState<'a>>,
    pub h: Option<HandshakeState>,
    pub cert_state: &'a CertState<'a>,
    pub peer_cert: Option<&'a NebulaCertificate>,
    pub initiator: bool,
    pub atomic_message_counter: u64,
    pub ready: bool,
    // todo(bonedaddy): do we need to implement?
    // https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/connection_state.go#L24
    // pub window: *Bits,
}

impl<'a> ConnectionState<'a> {
    pub fn new(
        cert_state: &'a CertState<'a>,
        initiator: bool,
        handshake_pattern: String,
        psk: Bytes,
        psk_stage: u8,
    ) -> Result<ConnectionState<'a>> {
        let mut cs = ConnectionState{
            e_key: None,
            d_key: None,
            h: None,
            cert_state,
            peer_cert: None,
            initiator,
            atomic_message_counter: 0,
            ready: false,
        };

        let ns: NoiseParams = handshake_pattern.parse()?;
        let handshake_state: HandshakeState = if initiator {
            Builder::new(ns).local_private_key(
                &cs.cert_state.inner.read().unwrap().private_key.clone()[..]
            ).psk(psk_stage, &psk).build_initiator()?
        } else {
            Builder::new(ns).psk(psk_stage, &psk).build_responder()?
        };
        cs.h = Some(handshake_state);
        Ok(cs)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use test_utils;
    use cert::cert_state;
    #[test]
    fn test_connection_state() {
        // wip https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/connection_state.go#L24
        let res = test_utils::create_test_ca_cert_client_cert();
        assert!(res.is_err() == false);
        let (
            mut client_cert,
            client_cert_x25519_public_key,
            client_cert_x25519_secret_key,
            client_cert_ed25519_keypair,
            ca_cert,
            ca_keypair,
        ) = res.unwrap();
        let cs = CertState::new(&mut client_cert, client_cert_ed25519_keypair.to_bytes().to_vec()).unwrap();
        let conn_state = ConnectionState::new(
            &cs,
            true,
            "Noise_XX_25519_AESGCM_SHA512".to_string(),
            Bytes::from("".to_string()),
            0,
        ).unwrap();
    }
}