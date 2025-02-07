#![allow(clippy::new_without_default)]

mod authenticator;
mod crypto;
mod entry;
mod import;

uniffi::include_scaffolding!("common");

pub fn library_version() -> String {
    proton_authenticator::library_version()
}

pub use authenticator::*;
pub use crypto::*;
pub use entry::*;
pub use import::*;
