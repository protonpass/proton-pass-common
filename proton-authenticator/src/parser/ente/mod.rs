use crate::parser::ThirdPartyImportError;

mod chacha_decrypt;
mod encrypted;
mod txt;

#[derive(Clone, Debug)]
pub enum EnteImportError {
    BadContent,
    BadPassword,
    Unsupported,
}

impl From<EnteImportError> for ThirdPartyImportError {
    fn from(value: EnteImportError) -> Self {
        match value {
            EnteImportError::BadContent => Self::BadContent,
            EnteImportError::BadPassword => Self::BadPassword,
            EnteImportError::Unsupported => Self::BadContent,
        }
    }
}

pub use encrypted::parse_ente_encrypted;
pub use txt::parse_ente_txt;

#[cfg(test)]
mod test {
    use crate::{AuthenticatorEntry, AuthenticatorEntryContent};
    use proton_pass_totp::algorithm::Algorithm;

    pub fn check_ente_entries(entries: Vec<AuthenticatorEntry>) {
        assert_eq!(entries.len(), 2);
        check_totp(
            &entries[0],
            "MyLabel256_8_15",
            "JVMVGRKDKJCVI===",
            "MyIssuer",
            Algorithm::SHA256,
            8,
            15,
        );
        check_totp(
            &entries[1],
            "MyLabelDefault",
            "JVMVGRKDKJCVI===",
            "MyIssuer",
            Algorithm::SHA1,
            6,
            30,
        );
    }

    fn check_totp(
        entry: &AuthenticatorEntry,
        label: &str,
        secret: &str,
        issuer: &str,
        algorithm: Algorithm,
        digits: u8,
        period: u16,
    ) {
        match &entry.content {
            AuthenticatorEntryContent::Totp(totp) => {
                assert_eq!(totp.digits.expect("should have digits"), digits);
                assert_eq!(totp.period.expect("should have period"), period);
                assert_eq!(totp.algorithm.expect("should have algorithm"), algorithm);
                assert_eq!(totp.secret, secret);
                assert_eq!(totp.label.clone().expect("should have label"), label);
                assert_eq!(totp.issuer.clone().expect("should have issuer"), issuer);
            }
            _ => panic!("should be AuthenticatorEntryContent::Totp"),
        }
    }
}
