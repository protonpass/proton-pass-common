use proton_pass_totp::error::TOTPError;
use proton_pass_totp::sanitizer::{human_readable_otp, sanitize_otp, sanitize_secret};

#[test]
fn human_readable_otp_test() {
    // Empty
    assert_eq!(human_readable_otp(""), "");

    // Invalid
    assert_eq!(human_readable_otp("invalid uri"), "invaliduri");

    // Unsupported protocol
    assert_eq!(human_readable_otp("https://proton.me"), "https://proton.me");

    // No label, no params
    assert_eq!(human_readable_otp("otpauth://totp/?secret=some_secret"), "some_secret");

    // With label, no params
    assert_eq!(
        human_readable_otp("otpauth://totp/john.doe?secret=some_secret"),
        "some_secret"
    );

    // No label, default params
    assert_eq!(
        human_readable_otp("otpauth://totp/?secret=some_secret&algorithm=SHA1&digits=6&period=30"),
        "some_secret"
    );

    // With label, default params
    assert_eq!(
        human_readable_otp("otpauth://totp/john.doe?secret=some_secret&algorithm=SHA1&digits=6&period=30"),
        "some_secret"
    );

    // No label, custom params
    assert_eq!(
        human_readable_otp("otpauth://totp/?secret=some_secret&algorithm=SHA256&digits=6&period=30"),
        "otpauth://totp/?secret=some_secret&algorithm=SHA256&digits=6&period=30"
    );

    // With label, custom params
    assert_eq!(
        human_readable_otp("otpauth://totp/john.doe?secret=some_secret&algorithm=SHA256&digits=6&period=30"),
        "otpauth://totp/john.doe?secret=some_secret&algorithm=SHA256&digits=6&period=30"
    )
}

#[test]
fn sanitize_otp_test() {
    // Empty input
    // => save as empty string
    assert_eq!(sanitize_otp("  ", None, None), Ok("".to_string()));

    // Invalid URI treated as secret
    // => sanitize secret and add default params
    assert_eq!(
        sanitize_otp(" some secret ", None, None),
        Ok("otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30".to_string())
    );

    // Valid TOTP URI
    // => normalize and fill in default params
    assert_eq!(
        sanitize_otp("otpauth://totp/?secret=somesecret", None, None),
        Ok("otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30".to_string())
    );

    // Valid non-TOTP URL
    // => return error
    assert_eq!(
        sanitize_otp(
            "https://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30",
            None,
            None
        ),
        Err(TOTPError::NotTotpUri)
    );

    // Raw secret with label
    // => sanitize secret and add default params with label
    assert_eq!(
        sanitize_otp("new secret", Some("john.doe".to_string()), None),
        Ok("otpauth://totp/john.doe?secret=newsecret&algorithm=SHA1&digits=6&period=30".to_string())
    );

    // Raw secret with issuer
    // => sanitize secret and add default params with issuer
    assert_eq!(
        sanitize_otp("new secret", None, Some("test".to_string())),
        Ok("otpauth://totp/?secret=newsecret&issuer=test&algorithm=SHA1&digits=6&period=30".to_string())
    );

    // Raw secret with label and issuer
    // => sanitize secret and add default params with both
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

    // Valid TOTP URI with custom params
    // => preserve custom params
    assert_eq!(
        sanitize_otp(
            "otpauth://totp/?secret=original_secret&algorithm=SHA256&digits=8&period=45",
            None,
            None
        ),
        Ok("otpauth://totp/?secret=original_secret&algorithm=SHA256&digits=8&period=45".to_string())
    );

    // Valid TOTP URI with custom params and provided label/issuer
    // => use provided label/issuer with custom params
    assert_eq!(
        sanitize_otp(
            "otpauth://totp/?secret=secret123&algorithm=SHA256&digits=8&period=45",
            Some("newuser".to_string()),
            Some("NewIssuer".to_string())
        ),
        Ok("otpauth://totp/newuser?secret=secret123&issuer=NewIssuer&algorithm=SHA256&digits=8&period=45".to_string())
    );

    // TOTP URI with empty secret
    // => return empty string
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
fn sanitizing_secret() {
    assert_eq!(sanitize_secret("ABC ABC ABC"), "ABCABCABC");
    assert_eq!(sanitize_secret("ABC-ABC-ABC"), "ABCABCABC");
    assert_eq!(sanitize_secret("ABC_ABC_ABC"), "ABCABCABC");
    assert_eq!(sanitize_secret(" ABC-ABC_ABC "), "ABCABCABC");
    assert_eq!(sanitize_secret("r9vTGRUEc9OBof8Gkp2x"), "R9VTGRUEC9OBOF8GKP2X");
    assert_eq!(sanitize_secret("MFRGG43FMZXW6==="), "MFRGG43FMZXW6");
}
