use proton_pass_common::login::{Login as CommonLogin, LoginError as CommonLoginError};

#[derive(uniffi::Record)]
pub struct Login {
    pub title: String,
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
    pub urls: Vec<String>,
}

impl From<Login> for CommonLogin {
    fn from(login: Login) -> Self {
        Self {
            title: login.title,
            username: login.username,
            password: login.password,
            totp: login.totp,
            urls: login.urls,
        }
    }
}

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum LoginError {
    InvalidTOTP,
    InvalidURL,
}

impl From<CommonLoginError> for LoginError {
    fn from(error: CommonLoginError) -> Self {
        match error {
            CommonLoginError::InvalidTOTP => LoginError::InvalidTOTP,
            CommonLoginError::InvalidURL => LoginError::InvalidURL,
        }
    }
}

#[derive(uniffi::Object)]
pub struct LoginValidator;

#[uniffi::export]
impl LoginValidator {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self, login: Login) -> Result<(), LoginError> {
        Ok(proton_pass_common::login::validate_login(CommonLogin::from(login))?)
    }
}
