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
    // assert_eq!(uri_for_saving("", ""), "");

    assert_eq!(
        uri_for_saving("invalid original", " some secret "),
        "otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30"
    );

    // assert_eq!(uri_for_saving("invalid original", "otpauth://totp/?secret=edited_secret"), "invalid edited");
}
