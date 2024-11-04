pub use proton_pass_common::host::{HostInfo, ParseHostError, parse};

pub struct HostParser;

impl HostParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, url: String) -> Result<HostInfo, ParseHostError> {
        parse(&url)
    }
}