#![allow(clippy::new_without_default)]

mod alias;
mod creditcard;
mod cxf;
mod cxp;
mod domain;
mod duplicate;
mod email;
mod file;
mod gunzip;
mod host;
#[cfg(feature = "resize-image")]
mod image;
mod invite;
mod login;
mod markdown;
mod merge;
mod passkey;
mod passkey_fetcher;
mod password;
mod qr;
mod serialization;
mod share;
mod sshkey;
mod totp;
mod twofa;
mod url_matching;
mod username;
mod wifi;

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn library_version() -> String {
    proton_pass_common::library_version()
}

pub use alias::*;
pub use creditcard::*;
pub use cxf::*;
pub use cxp::*;
pub use domain::*;
pub use duplicate::*;
pub use email::*;
pub use file::*;
pub use gunzip::*;
pub use host::*;
#[cfg(feature = "resize-image")]
pub use image::*;
pub use invite::*;
pub use login::*;
pub use markdown::*;
pub use merge::*;
pub use passkey::*;
pub use passkey_fetcher::*;
pub use password::*;
pub use qr::*;
pub use serialization::*;
pub use share::*;
pub use sshkey::*;
pub use totp::*;
pub use twofa::*;
pub use url_matching::*;
pub use username::*;
pub use wifi::*;

pub use proton_pass_types::*;
