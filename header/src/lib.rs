use std::{collections::HashMap, hash::Hash};
use byteorder::{ByteOrder, BigEndian};
use errors::HeaderError;
use once_cell::sync::Lazy;
use anyhow::Result;


pub mod errors;

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
    Unknown = 255,
}

impl From<u8> for NebulaMessageType {
    fn from(num: u8) -> NebulaMessageType {
        match num {
            0 => NebulaMessageType::Handshake,
            _ => NebulaMessageType::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum NebulaMessageSubType {
    TestRequest = 0,
    TestReply = 1,
    HandshakeIXPSK0 = 2,
    Unknown = 255,
}

impl From<u8> for NebulaMessageSubType {
    fn from(num: u8) -> NebulaMessageSubType {
        match num {
            0 => NebulaMessageSubType::TestRequest,
            _ => NebulaMessageSubType::Unknown,
        }
    }
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

pub fn header_encode(
    data: &[u8], 
    v: u8, 
    t: NebulaMessageType, 
    st: NebulaMessageSubType, 
    ri: u32, 
    c: u64,
)   -> Vec<u8> {
    let mut data_part = data[0..HEADER_LEN as usize].to_vec();
    data_part[0] = v << 4 | (t as u8 & 0x0f);
    data_part[1] = st as u8;
    BigEndian::write_u16(&mut data_part[2..4], 0);
    BigEndian::write_u32(&mut data_part[4..8], ri);
    BigEndian::write_u64(&mut data_part[8..16], c);
    data_part
}

impl Header {
    pub fn new(data: &[u8]) -> Result<Header> {
        Header::parse(data)
    }
    // turns header into bytes
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(header_encode(
            data, 
        self.version,
        self.typ,
        self.sub_type,
        self.remote_index,
        self.message_counter
        ))
    }
    // helper function to parse given bytes into a new header struct
    pub fn parse(data: &[u8]) -> Result<Header> {
        let mut default_header = Header::default();
        if data.len() < HEADER_LEN as usize {
            return Err(HeaderError::HeaderTooShort.into());
        }
        default_header.version = data[0] >> 4 & 0x0f;
        default_header.typ = NebulaMessageType::from(data[0] & 0x0f);
        default_header.sub_type = NebulaMessageSubType::from(data[1]);
        default_header.reserved = BigEndian::read_u16(&data[2..4]);
        default_header.remote_index = BigEndian::read_u32(&data[4..8]);
        default_header.message_counter = BigEndian::read_u64(&data[8..16]);
        Ok(default_header)
    }
}

impl Default for Header {
    fn default() -> Self {
        Header{
            version: 0,
            typ: NebulaMessageType::TestRemote,
            sub_type: NebulaMessageSubType::TestReply,
            reserved: 0,
            remote_index: 0,
            message_counter: 0,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    fn test_encode() {
        let expected_bytes: [u8; 16] = [0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9];
        let expected_header = Header{
            version: 5,
            typ: NebulaMessageType::from(5),
            sub_type: NebulaMessageSubType::from(0),
            reserved: 0,
            remote_index: 10,
            message_counter: 9,
        };

        let expected_header_2 = expected_header.encode(&expected_bytes);
        assert!(expected_header_2.is_err() == false);
        let expected_header_2_bytes = expected_header_2.unwrap();
        let expected_header_2 = Header::parse(&expected_header_2_bytes);
        assert!(expected_header_2.is_err() == false);
        println!("header 1 {:#?}", expected_header);
        println!("header 2 {:#?}", expected_header_2);
    }
}
