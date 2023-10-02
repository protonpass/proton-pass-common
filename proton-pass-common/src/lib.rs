pub mod alias_prefix;
pub mod email;
pub mod login;
pub mod password;
pub mod totp;
pub mod utils;

pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
