pub mod alias_prefix;
pub mod creditcard;
pub mod domain;
pub mod email;
pub mod file;
pub mod host;
pub mod invite;
pub mod login;
pub mod passkey;
pub mod password;
pub mod totp;
pub mod twofa;

pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub use passkey_types;
