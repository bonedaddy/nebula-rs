use std::{collections::HashMap, hash::Hash};
use byteorder::{ByteOrder, BigEndian};
use once_cell::sync::Lazy;

// version 1 header
const VERSION: u8 = 1;
const HEADER_LEN: u8 = 16;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum NebulaMessageType {
    Handshake = 0,
    Message = 1,
    RecvError = 2,
    LightHouse = 3,
    Test = 4,
    CloseTunnel = 5,
    //TODO These are deprecated as of 06/12/2018 - NB
    TestRemote = 6,
    TestRemoteReply = 7,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum NebulaMessageSubType {
    TestRequest = 0,
    TestReply = 1,
    HandshakeIXPSK0 = 2,
}


pub static TYPE_MAP: Lazy<HashMap<NebulaMessageType, &'static str>> = Lazy::new(|| {
    let mut m: HashMap<NebulaMessageType, &'static str> = HashMap::new();
    m.insert(NebulaMessageType::Handshake, "handshake");
    m.insert(NebulaMessageType::Message, "message");
    m.insert(NebulaMessageType::RecvError, "recvError");
    m.insert(NebulaMessageType::LightHouse, "lightHouse");
    m.insert(NebulaMessageType::Test, "test");
    m.insert(NebulaMessageType::CloseTunnel, "closeTunnel");
    m.insert(NebulaMessageType::TestRemote, "testRemote");
    m.insert(NebulaMessageType::TestRemoteReply, "testRemoteReply");
    m
});

pub static SUB_TYPE_MAP: Lazy<HashMap<NebulaMessageType, HashMap<NebulaMessageSubType, String>>> = Lazy::new(|| {
    let mut m: HashMap<NebulaMessageType, HashMap<NebulaMessageSubType, String>> = HashMap::new();
    m.insert(NebulaMessageType::Message, sub_type_none_map());
    m.insert(NebulaMessageType::RecvError, sub_type_none_map());
    m.insert(NebulaMessageType::LightHouse, sub_type_none_map());
    m.insert(NebulaMessageType::Test, sub_type_none_map());
    m.insert(NebulaMessageType::CloseTunnel, sub_type_none_map());
    m.insert(NebulaMessageType::Handshake, sub_type_handshake());
    // todo(bonedaddy): these are deprecated
    m.insert(NebulaMessageType::TestRemote, sub_type_none_map());
    m.insert(NebulaMessageType::TestRemoteReply, sub_type_none_map());
    m
});


pub static SUB_TYPE_TEST_MAP: Lazy<HashMap<NebulaMessageSubType, &'static str>> = Lazy::new(|| {
    let mut m: HashMap<NebulaMessageSubType, &'static str> = HashMap::new();
    m.insert(NebulaMessageSubType::TestRequest, "testRequest");
    m.insert(NebulaMessageSubType::TestReply, "testReply");
    m
});

// meant to replicate you might have meant to construct one of the enum's non-tuple variants
// where 0 is the none type
pub static SUB_TYPE_NONE_MAP: Lazy<HashMap<NebulaMessageSubType, &str>> = Lazy::new(|| {
    let mut m: HashMap<NebulaMessageSubType, &'static str> = HashMap::new();
    m.insert(NebulaMessageSubType::TestRequest, "none");
    m
}); 

pub fn sub_type_none_map() -> HashMap<NebulaMessageSubType, String> {
    let mut m = HashMap::new();
    m.insert(NebulaMessageSubType::TestRequest, "none".to_string());
    m
}

fn sub_type_handshake() -> HashMap<NebulaMessageSubType, String> {
    let mut m = HashMap::new();
    m.insert(NebulaMessageSubType::HandshakeIXPSK0, "ix_psk0".to_string());
    m
}


#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    // typ = type as we can have type sine it ias a keyword
    pub typ: NebulaMessageType,
    pub sub_type: NebulaMessageSubType,
    pub reserved: u16,
    pub remote_index: u32,
    pub message_counter: u64,
}

impl Header {
    pub fn encode(
        data: &[u8], 
        version: u8, 
        typ: NebulaMessageType, 
        sub_type: NebulaMessageSubType, 
        reserved: u16, 
        remote_index: u32, 
        message_counter: u64,
    )   {
        let mut data_part = data[0..HEADER_LEN as usize].to_vec();
        data_part[0] = version << 4 | (typ as u8 & 0x0f);
        data_part[1] = sub_type as u8;
        BigEndian::write_u16(&mut data_part, 0);
        BigEndian::write_u32(&mut data_part, remote_index);
        BigEndian::write_u64(&mut data_part, message_counter);
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
