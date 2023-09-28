use proton_pass_common::totp::sanitizer::uri_for_saving;

#[test]
fn invalid() {
    // Given
    let uri = "invalid uri";

    // When
    let sanizited_uri = uri_for_saving(uri);

    // Then
    assert_eq!(sanizited_uri, uri);
}

#[test]
fn no_params() {
    // Given
    let uri = "otpauth://totp/?secret=somesecret";

    // When
    let sanitized_uri = uri_for_saving(uri);

    // Then
    assert_eq!(
        sanitized_uri,
        "otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30"
    );
}

#[test]
fn default_params() {
    // Given
    let uri = "otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30";

    // When
    let sanitized_uri = uri_for_saving(uri);

    // Then
    assert_eq!(
        sanitized_uri,
        "otpauth://totp/?secret=somesecret&algorithm=SHA1&digits=6&period=30"
    );
}

#[test]
fn custom_params() {
    // Given
    let uri = "otpauth://totp/john.doe?secret=somesecret&algorithm=SHA256&digits=8&period=30";

    // When
    let sanitized_uri = uri_for_saving(uri);

    // Then
    assert_eq!(
        sanitized_uri,
        "otpauth://totp/john.doe?secret=somesecret&algorithm=SHA256&digits=8&period=30"
    );
}
