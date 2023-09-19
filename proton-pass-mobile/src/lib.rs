use proton_pass_common::login::Login;

pub fn is_email_valid(email: String) -> bool {
    proton_pass_common::email::is_email_valid(&email)
}

pub fn is_login_valid(login: Login) -> Result<(), proton_pass_common::login::LoginError> {
    proton_pass_common::login::validate_login(login)
}
