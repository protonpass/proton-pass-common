use proton_pass_common::totp::sanitizer::{uri_for_editing, uri_for_saving};

#[test]
fn for_editing() {
    // Empty
    assert_eq!(uri_for_editing(""), "");

    // Invalid
    assert_eq!(uri_for_editing("invalid uri"), "invalid uri");

    // No label, no params
    assert_eq!(uri_for_editing("otpauth://totp/?secret=some_secret"), "some_secret");

    // With label, no params
    assert_eq!(
        uri_for_editing("otpauth://totp/john.doe?secret=some_secret"),
        "some_secret"
    );

    // No label, default params
    assert_eq!(
        uri_for_editing("otpauth://totp/?secret=some_secret&algorithm=SHA1&digits=6&period=30"),
        "some_secret"
    );

    // With label, default params
    assert_eq!(
        uri_for_editing("otpauth://totp/john.doe?secret=some_secret&algorithm=SHA1&digits=6&period=30"),
        "some_secret"
    );

    // No label, custom params
    assert_eq!(
        uri_for_editing("otpauth://totp/?secret=some_secret&algorithm=SHA256&digits=6&period=30"),
        "otpauth://totp/?secret=some_secret&algorithm=SHA256&digits=6&period=30"
    );

    // With label, custom params
    assert_eq!(
        uri_for_editing("otpauth://totp/john.doe?secret=some_secret&algorithm=SHA256&digits=6&period=30"),
        "otpauth://totp/john.doe?secret=some_secret&algorithm=SHA256&digits=6&period=30"
    )
}

#[test]
fn for_saving() {
    // Invalid original, edit with secret only
    // => sanitize secret and add default params
    assert_eq!(
        uri_for_saving("invalid original", " some secret "),
        "otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30"
    );

    // Invalid original, edit with valid URI
    // => save the edited URI as-is
    assert_eq!(
        uri_for_saving(
            "invalid original",
            "otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30"
        ),
        "otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30"
    );

    // Valid original with no params, edit with secret only
    // => sanitize secret and add default params
    assert_eq!(
        uri_for_saving("otpauth://totp/?secret=original_secret", "new secret"),
        "otpauth://totp/?secret=newsecret&algorithm=SHA1&digits=6&period=30"
    );

    // Valid original with issuer and no params, edit with secret only
    // => sanitize secret, use the original issuer and add default params
    assert_eq!(
        uri_for_saving(
            "otpauth://totp/?secret=original_secret&issuer=original_issuer",
            "new secret"
        ),
        "otpauth://totp/?secret=newsecret&issuer=original_issuer&algorithm=SHA1&digits=6&period=30"
    );

    // Valid original with default params, edit with secret only
    // => sanitize secret and add default params
    assert_eq!(
        uri_for_saving(
            "otpauth://totp/?secret=original_secret&algorithm=SHA1&digits=6&period=30",
            "new secret"
        ),
        "otpauth://totp/?secret=newsecret&algorithm=SHA1&digits=6&period=30"
    );

    // Valid original with custom params, edit with secret only
    // => sanitize secret and add default params
    assert_eq!(
        uri_for_saving(
            "otpauth://totp/?secret=original_secret&algorithm=SHA256&digits=8&period=45",
            "new secret"
        ),
        "otpauth://totp/?secret=newsecret&algorithm=SHA1&digits=6&period=30"
    );

    // Valid original with custom params, edit with custom params and issuer
    // => save the edited URI as-is
    assert_eq!(
        uri_for_saving(
            "otpauth://totp/?secret=original_secret&algorithm=SHA256&digits=8&period=45",
            "otpauth://totp/?secret=new_secret&issuer=new_issuer&algorithm=SHA1&digits=8&period=45"
        ),
        "otpauth://totp/?secret=new_secret&issuer=new_issuer&algorithm=SHA1&digits=8&period=45"
    );
}
