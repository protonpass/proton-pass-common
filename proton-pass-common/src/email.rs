pub fn is_email_valid(email: &str) -> bool {
    email_address::EmailAddress::is_valid(email)
}
