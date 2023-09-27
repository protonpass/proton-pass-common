use proton_pass_common::totp::algorithm::Algorithm::SHA512;
use proton_pass_common::totp::components::TOTPComponents;
use proton_pass_common::totp::error::TOTPError;

fn make_sut(uri: &str) -> Result<TOTPComponents, TOTPError> {
    TOTPComponents::from_uri(uri)
}

#[test]
fn invalid_scheme() {
    // Given
    let uri = "https://totp/john.doe%40example.com?secret=somesecret&algorithm=SHA1&digits=8&period=30";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Err(error) => assert_eq!(error, TOTPError::InvalidScheme("https".to_string())),
        _ => panic!("Should not be able to parse"),
    }
}

#[test]
fn invalid_authority() {
    // Given
    let uri = "otpauth://hotp/john.doe%40example.com?secret=somesecret&algorithm=SHA1&digits=8&period=30";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Err(error) => assert_eq!(error, TOTPError::InvalidAuthority("hotp".to_string())),
        _ => panic!("Should not be able to parse"),
    }
}

#[test]
fn no_authority() {
    // Given
    let uri = "otpauth://?secret=somesecret&algorithm=SHA1&digits=8&period=30";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Err(error) => assert_eq!(error, TOTPError::NoAuthority),
        _ => panic!("Should not be able to parse"),
    }
}

#[test]
fn no_queries() {
    // Given
    let uri = "otpauth://totp/";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Err(error) => assert_eq!(error, TOTPError::NoQueries),
        _ => panic!("Should not be able to parse"),
    }
}

#[test]
fn no_secret() {
    // Given
    let uri = "otpauth://totp/john.doe%40example.com?algorithm=SHA1&digits=8&period=30";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Err(error) => assert_eq!(error, TOTPError::NoSecret),
        _ => panic!("Should not be able to parse"),
    }
}

#[test]
fn empty_secret() {
    // Given
    let uri = "otpauth://totp/john.doe%40example.com?secret=&algorithm=SHA1&digits=8&period=30";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Err(error) => assert_eq!(error, TOTPError::EmptySecret),
        _ => panic!("Should not be able to parse"),
    }
}

#[test]
fn invalid_algorithm() {
    // Given
    let uri = "otpauth://totp/john.doe%40example.com?secret=somesecret&algorithm=SHA128&digits=8&period=30";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Err(error) => assert_eq!(error, TOTPError::InvalidAlgorithm("SHA128".to_string())),
        _ => panic!("Should not be able to parse"),
    }
}

#[test]
fn explicit_params() {
    // Given
    let uri =
        "otpauth://totp/john.doe%40example.com?secret=somesecret&issuer=ProtonMail&algorithm=SHA512&digits=8&period=45";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Ok(components) => {
            assert_eq!(components.label, Some("john.doe%40example.com".to_string()));
            assert_eq!(components.secret, "somesecret");
            assert_eq!(components.issuer, Some("ProtonMail".to_string()));
            assert_eq!(components.algorithm, Some(SHA512));
            assert_eq!(components.digits, Some(8));
            assert_eq!(components.period, Some(45));
        }
        _ => panic!("Should be able to parse"),
    }
}

#[test]
fn implicit_params() {
    // Given
    let uri = "otpauth://totp/?secret=somesecret";

    // When
    let sut = make_sut(uri);

    // Then
    match sut {
        Ok(components) => {
            assert_eq!(components.label, None);
            assert_eq!(components.secret, "somesecret");
            assert_eq!(components.issuer, None);
            assert_eq!(components.algorithm, None);
            assert_eq!(components.digits, None);
            assert_eq!(components.period, None);
        }
        _ => panic!("Should be able to parse"),
    }
}
