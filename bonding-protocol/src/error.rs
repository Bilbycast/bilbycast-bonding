//! Error types for `bonding-protocol`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BondError {
    #[error("bond packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("unsupported bond protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid bond header magic: expected 0x{expected:08x}, got 0x{actual:08x}")]
    InvalidMagic { expected: u32, actual: u32 },

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, BondError>;
