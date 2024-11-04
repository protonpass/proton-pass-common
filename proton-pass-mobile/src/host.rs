pub use proton_pass_common::host::{parse, HostInfo, ParseHostError};

pub struct HostParser;

impl HostParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, url: String) -> Result<HostInfo, ParseHostError> {
        parse(&url)
    }
}
