pub fn is_email_valid(email: String) -> bool {
    proton_pass_common::email::is_email_valid(&email)
}
