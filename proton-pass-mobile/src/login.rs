pub use proton_pass_common::login::{Login, LoginError};

pub struct LoginValidator;

impl LoginValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self, login: Login) -> Result<(), LoginError> {
        proton_pass_common::login::validate_login(login)
    }
}
