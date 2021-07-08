use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("header too short")]
    HeaderTooShort,
    #[error("invalid nebula message type")]
    InvalidNebulaMessageType,
}