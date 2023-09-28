use proton_pass_common::totp::sanitizer::uri_for_editing;

#[test]
fn invalid_uri() {
    // Given
    let uri = "invalid_uri";

    // When
    let sanitized_uri = uri_for_editing(uri);

    // Then
    assert_eq!(sanitized_uri, uri)
}

#[test]
fn implicit_default_params() {
    // Given
    let uri = "otpauth://totp/?secret=somesecret";

    // When
    let sanitized_uri = uri_for_editing(uri);

    // Then
    assert_eq!(sanitized_uri, "somesecret")
}

#[test]
fn explicit_default_params() {
    // Given
    let uri = "otpauth://totp/john.doe%40example.com?secret=somesecret&algorithm=SHA1&digits=6&period=30";

    // When
    let sanitized_uri = uri_for_editing(uri);

    // Then
    assert_eq!(sanitized_uri, "somesecret")
}

#[test]
fn custom_params() {
    // Given
    let uri = "otpauth://totp/john.doe%40example.com?secret=somesecret&algorithm=SHA256&digits=6&period=30";

    // When
    let sanitized_uri = uri_for_editing(uri);

    // Then
    assert_eq!(sanitized_uri, uri)
}
