mod db;
mod encrypted;
mod json;
mod txt;

#[derive(Clone, Debug)]
pub enum AegisImportError {
    Unsupported,
    BadContent,
    BadPassword,
    NotEncryptedBackupWithPassword,
    EncryptedBackupWithNoPassword,
    UnableToDecrypt,
}

pub use json::parse_aegis_json;
pub use txt::parse_aegis_txt;

#[cfg(test)]
mod test {
    use crate::authenticator::{AuthenticatorEntry, AuthenticatorEntryContent};
    use crate::totp::algorithm::Algorithm;

    pub fn check_export_matches(entries: Vec<AuthenticatorEntry>) {
        assert_eq!(entries.len(), 3);
        check_totp(&entries[0].content, 15, 8, Algorithm::SHA256);
        check_totp(&entries[1].content, 30, 6, Algorithm::SHA1);
        check_steam(&entries[2].content);
    }

    fn check_totp(entry: &AuthenticatorEntryContent, period: u16, digits: u8, algorithm: Algorithm) {
        match entry {
            AuthenticatorEntryContent::Totp(totp) => {
                assert_eq!(totp.period.expect("should have period"), period);
                assert_eq!(totp.digits.expect("should have digits"), digits);
                assert_eq!(totp.algorithm.expect("should have algorithm"), algorithm);
            }
            _ => panic!("Should be AuthenticatorEntryContent::Totp"),
        };
    }

    fn check_steam(entry: &AuthenticatorEntryContent) {
        match entry {
            AuthenticatorEntryContent::Steam(_) => {}
            _ => panic!("Should be AuthenticatorEntryContent::Steam"),
        };
    }
}
