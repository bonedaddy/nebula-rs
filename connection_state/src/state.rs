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
            Builder::new(ns).psk(psk_stage, &psk).build_initiator()?
        } else {
            Builder::new(ns).psk(psk_stage, &psk).build_responder()?
        };
        cs.h = Some(handshake_state);
        Ok(cs)
    }
}


#[cfg(test)]
mod test {
    #[test]
    fn test_connection_state() {
        // wip https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/connection_state.go#L24
    }
}