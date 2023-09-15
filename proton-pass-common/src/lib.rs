use email_address::*;

pub fn is_email_valid(email: &str) -> bool {
    EmailAddress::is_valid(email)
}
