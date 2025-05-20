#![allow(clippy::new_without_default)]

mod authenticator;
mod benchmark;
mod crypto;
mod entry;
mod generator;
mod import;
mod issuer_mapper;
mod log;
mod operations;
mod ordering;

uniffi::include_scaffolding!("common");

pub fn library_version() -> String {
    proton_authenticator::library_version()
}

pub use authenticator::*;
pub use benchmark::*;
pub use crypto::*;
pub use entry::*;
pub use generator::*;
pub use import::*;
pub use issuer_mapper::*;
pub use log::*;
pub use operations::*;
pub use ordering::*;
