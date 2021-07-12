use snow::TransportState;

pub struct CipherState<'a> {
    pub transport_state: &'a TransportState,
}

impl<'a> CipherState<'a> {
    pub fn new(ts: &'a TransportState) -> Self {
        Self {
            transport_state: ts,
        }
    }
}