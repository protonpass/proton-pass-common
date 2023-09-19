#![allow(dead_code, unused_variables)]

use proton_pass_derive::Error;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct Login {
    title: String,
    username: String,
    password: String,
    totp: Option<String>,
    urls: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoginError {
    InvalidTOTP,
    InvalidURL,
}

pub fn validate_login(login: Login) -> Result<(), LoginError> {
    Err(LoginError::InvalidTOTP)
}
