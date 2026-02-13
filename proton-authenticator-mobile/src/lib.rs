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
mod qr;

uniffi::setup_scaffolding!();

// Re-export scaffolding from dependent crates to make their types available
proton_authenticator::uniffi_reexport_scaffolding!();
proton_pass_totp::uniffi_reexport_scaffolding!();

#[uniffi::export]
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
pub use qr::*;
