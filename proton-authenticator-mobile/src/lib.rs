#![allow(clippy::new_without_default)]

mod authenticator;

uniffi::include_scaffolding!("common");

pub fn library_version() -> String {
    proton_authenticator::library_version()
}

pub use authenticator::*;
