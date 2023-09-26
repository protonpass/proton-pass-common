use proton_pass_common::otp::{OTPAlgorithm, OTPError, OTPType};
use proton_pass_common::otp::OTPAlgorithm::{SHA1, SHA256, SHA512};
use proton_pass_common::otp::OTPType::{HOTP, TOTP};

#[test]
fn parse_otp_type() {
    assert_eq!(OTPType::parse("totp"), Ok(TOTP));
    assert_eq!(OTPType::parse("TOTP"), Ok(TOTP));

    assert_eq!(OTPType::parse("hotp"), Ok(HOTP));
    assert_eq!(OTPType::parse("HOTP"), Ok(HOTP));

    assert_eq!(OTPType::parse("otp"), Err(OTPError::InvalidType));
}

#[test]
fn parse_otp_algorithm() {
    assert_eq!(OTPAlgorithm::parse("sha1"), Ok(SHA1));
    assert_eq!(OTPAlgorithm::parse("SHA1"), Ok(SHA1));

    assert_eq!(OTPAlgorithm::parse("sha256"), Ok(SHA256));
    assert_eq!(OTPAlgorithm::parse("SHA256"), Ok(SHA256));

    assert_eq!(OTPAlgorithm::parse("sha512"), Ok(SHA512));
    assert_eq!(OTPAlgorithm::parse("SHA512"), Ok(SHA512));

    assert_eq!(OTPAlgorithm::parse("sha"), Err(OTPError::InvalidAlgorithm));
}