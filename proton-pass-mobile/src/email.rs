#[derive(uniffi::Object)]
pub struct EmailValidator;

#[uniffi::export]
impl EmailValidator {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn is_email_valid(&self, email: String) -> bool {
        proton_pass_common::email::is_email_valid(&email)
    }
}
