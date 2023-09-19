#![allow(dead_code, unused_variables)]

use proton_pass_derive::Error;

pub struct Login {
    pub title: String,
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
    pub urls: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoginError {
    InvalidTOTP,
    InvalidURL,
}

pub fn validate_login(login: Login) -> Result<(), LoginError> {
    Err(LoginError::InvalidTOTP)
}
