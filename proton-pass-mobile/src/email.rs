pub struct EmailValidator;

impl EmailValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn is_email_valid(&self, email: String) -> bool {
        proton_pass_common::email::is_email_valid(&email)
    }
}
