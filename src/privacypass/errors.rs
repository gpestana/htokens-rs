/// Errors for humanity tokens lib

use core::fmt;
use std::fmt::Display;

#[derive(Debug)]
/// Wrapper for humanity tokens protocol errors
pub struct ProtocolError {
    details: String,
}

impl ProtocolError {
    pub fn new(msg: &str) -> Self {
        ProtocolError {
            details: msg.to_string(),
        }
    }
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error: {}", self.details)
    }
}
