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
pub mod twofa;

pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub use proton_pass_totp as totp;
