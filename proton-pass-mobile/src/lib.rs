#![allow(clippy::new_without_default)]

mod alias;
mod email;
mod login;
mod password;
mod totp;

uniffi::include_scaffolding!("common");

pub fn library_version() -> String {
    proton_pass_common::library_version()
}

pub use alias::*;
pub use email::*;
pub use login::*;
pub use password::*;
pub use totp::*;
