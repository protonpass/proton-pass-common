#![allow(clippy::new_without_default)]

mod alias;
mod creditcard;
mod email;
mod invite;
mod login;
mod passkey;
mod password;
mod totp;
mod twofa;

uniffi::include_scaffolding!("common");

pub fn library_version() -> String {
    proton_pass_common::library_version()
}

pub use alias::*;
pub use creditcard::*;
pub use email::*;
pub use invite::*;
pub use login::*;
pub use passkey::*;
pub use password::*;
pub use totp::*;
pub use twofa::*;
