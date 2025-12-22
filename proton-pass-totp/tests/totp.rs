use proton_pass_totp::error::TOTPError;
use proton_pass_totp::sanitizer::{human_readable_otp, sanitize_otp, sanitize_secret};

#[test]
fn human_readable_otp_empty() {
    assert_eq!(human_readable_otp(""), "");
}

#[test]
fn human_readable_otp_invalid() {
    assert_eq!(human_readable_otp("invalid uri"), "invaliduri");
}

#[test]
fn human_readable_otp_unsupported_protocol() {
    assert_eq!(human_readable_otp("https://proton.me"), "https://proton.me");
}

#[test]
fn human_readable_otp_no_label_no_params() {
    assert_eq!(human_readable_otp("otpauth://totp/?secret=some_secret"), "some_secret");
}

#[test]
fn human_readable_otp_with_label_no_params() {
    assert_eq!(
        human_readable_otp("otpauth://totp/john.doe?secret=some_secret"),
        "some_secret"
    );
}

#[test]
fn human_readable_otp_no_label_default_params() {
    assert_eq!(
        human_readable_otp("otpauth://totp/?secret=some_secret&algorithm=SHA1&digits=6&period=30"),
        "some_secret"
    );
}

#[test]
fn human_readable_otp_with_label_default_params() {
    assert_eq!(
        human_readable_otp("otpauth://totp/john.doe?secret=some_secret&algorithm=SHA1&digits=6&period=30"),
        "some_secret"
    );
}

#[test]
fn human_readable_otp_no_label_custom_params() {
    assert_eq!(
        human_readable_otp("otpauth://totp/?secret=some_secret&algorithm=SHA256&digits=6&period=30"),
        "otpauth://totp/?secret=some_secret&algorithm=SHA256&digits=6&period=30"
    );
}

#[test]
fn human_readable_otp_with_label_custom_params() {
    assert_eq!(
        human_readable_otp("otpauth://totp/john.doe?secret=some_secret&algorithm=SHA256&digits=6&period=30"),
        "otpauth://totp/john.doe?secret=some_secret&algorithm=SHA256&digits=6&period=30"
    );
}

#[test]
fn sanitize_otp_empty_input() {
    assert_eq!(sanitize_otp("  ", None, None), Ok("".to_string()));
}

#[test]
fn sanitize_otp_invalid_uri_treated_as_secret() {
    assert_eq!(
        sanitize_otp(" some secret ", None, None),
        Ok("otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30".to_string())
    );
}

#[test]
fn sanitize_otp_valid_totp_uri() {
    assert_eq!(
        sanitize_otp("otpauth://totp/?secret=somesecret", None, None),
        Ok("otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30".to_string())
    );
}

#[test]
fn sanitize_otp_valid_non_totp_url() {
    assert_eq!(
        sanitize_otp(
            "https://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30",
            None,
            None
        ),
        Err(TOTPError::NotTotpUri)
    );
}

#[test]
fn sanitize_otp_raw_secret_with_label() {
    assert_eq!(
        sanitize_otp("new secret", Some("john.doe".to_string()), None),
        Ok("otpauth://totp/john.doe?secret=newsecret&algorithm=SHA1&digits=6&period=30".to_string())
    );
}

#[test]
fn sanitize_otp_raw_secret_with_issuer() {
    assert_eq!(
        sanitize_otp("new secret", None, Some("test".to_string())),
        Ok("otpauth://totp/?secret=newsecret&issuer=test&algorithm=SHA1&digits=6&period=30".to_string())
    );
}

#[test]
fn sanitize_otp_raw_secret_with_label_and_issuer() {
    assert_eq!(
        sanitize_otp(
            "new secret",
            Some("test_label".to_string()),
            Some("test_issuer".to_string())
        ),
        Ok(
            "otpauth://totp/test_label?secret=newsecret&issuer=test_issuer&algorithm=SHA1&digits=6&period=30"
                .to_string()
        )
    );
}

#[test]
fn sanitize_otp_valid_totp_uri_with_custom_params() {
    assert_eq!(
        sanitize_otp(
            "otpauth://totp/?secret=original_secret&algorithm=SHA256&digits=8&period=45",
            None,
            None
        ),
        Ok("otpauth://totp/?secret=original_secret&algorithm=SHA256&digits=8&period=45".to_string())
    );
}

#[test]
fn sanitize_otp_valid_totp_uri_with_custom_params_and_provided_label_issuer() {
    assert_eq!(
        sanitize_otp(
            "otpauth://totp/?secret=secret123&algorithm=SHA256&digits=8&period=45",
            Some("newuser".to_string()),
            Some("NewIssuer".to_string())
        ),
        Ok("otpauth://totp/newuser?secret=secret123&issuer=NewIssuer&algorithm=SHA256&digits=8&period=45".to_string())
    );
}

#[test]
fn sanitize_otp_totp_uri_with_empty_secret() {
    assert_eq!(
        sanitize_otp(
            "otpauth://totp/?secret=&algorithm=SHA256&digits=6&period=30",
            None,
            None
        ),
        Ok("".to_string())
    );
}

#[test]
fn sanitize_secret_removes_spaces() {
    assert_eq!(sanitize_secret("ABC ABC ABC"), "ABCABCABC");
}

#[test]
fn sanitize_secret_removes_dashes() {
    assert_eq!(sanitize_secret("ABC-ABC-ABC"), "ABCABCABC");
}

#[test]
fn sanitize_secret_removes_underscores() {
    assert_eq!(sanitize_secret("ABC_ABC_ABC"), "ABCABCABC");
}

#[test]
fn sanitize_secret_removes_mixed_formatting() {
    assert_eq!(sanitize_secret(" ABC-ABC_ABC "), "ABCABCABC");
}

#[test]
fn sanitize_secret_converts_to_uppercase() {
    assert_eq!(sanitize_secret("r9vTGRUEc9OBof8Gkp2x"), "R9VTGRUEC9OBOF8GKP2X");
}

#[test]
fn sanitize_secret_removes_padding() {
    assert_eq!(sanitize_secret("MFRGG43FMZXW6==="), "MFRGG43FMZXW6");
}