#![allow(unexpected_cfgs)]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub mod alias_prefix;
pub mod creditcard;
pub mod domain;
pub mod email;
pub mod file;
pub mod host;
pub mod invite;
pub mod login;
pub mod passkey;
pub use passkey_types;
pub mod password;
pub mod qr;
pub mod string_modifiers;
pub mod share;
pub mod sshkey;
pub mod twofa;
pub mod username;
pub mod wifi;

pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub use proton_pass_totp as totp;
pub use qrcode;
pub use url;
