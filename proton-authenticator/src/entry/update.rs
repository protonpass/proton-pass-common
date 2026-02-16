use crate::{
    AuthenticatorEntry, AuthenticatorEntryError, AuthenticatorEntrySteamCreateParameters,
    AuthenticatorEntryTotpCreateParameters,
};
use proton_pass_derive::ffi_type;
use proton_pass_totp::Algorithm;

#[ffi_type]
#[derive(Clone, Debug)]
pub enum AuthenticatorEntryType {
    Totp,
    Steam,
}

#[ffi_type]
#[derive(Clone, Debug)]
pub struct AuthenticatorEntryUpdateContents {
    pub name: String,
    pub secret: String,
    pub issuer: String,
    pub period: u16,
    pub digits: u8,
    pub algorithm: Algorithm,
    pub note: Option<String>,
    pub entry_type: AuthenticatorEntryType,
}

impl AuthenticatorEntry {
    pub fn update(&mut self, contents: AuthenticatorEntryUpdateContents) -> Result<(), AuthenticatorEntryError> {
        let new_entry = match contents.entry_type {
            AuthenticatorEntryType::Totp => {
                let new_totp_contents = AuthenticatorEntryTotpCreateParameters {
                    name: contents.name,
                    secret: contents.secret,
                    issuer: contents.issuer,
                    period: Some(contents.period),
                    digits: Some(contents.digits),
                    algorithm: Some(contents.algorithm),
                    note: contents.note,
                };
                Self::new_totp_entry_from_params(new_totp_contents)
            }
            AuthenticatorEntryType::Steam => {
                let new_steam_contents = AuthenticatorEntrySteamCreateParameters {
                    name: contents.name,
                    secret: contents.secret,
                    note: contents.note,
                };

                Self::new_steam_entry_from_params(new_steam_contents)
            }
        }?;

        self.note = new_entry.note;
        self.content = new_entry.content;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::AuthenticatorEntryContent;

    #[test]
    fn can_update_totp_entry() {
        let mut entry = AuthenticatorEntry::from_uri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA1&digits=8&period=15",
            Some("a note".to_string()),
        )
        .unwrap();

        let original_id = entry.id.clone();

        let update_params = AuthenticatorEntryUpdateContents {
            name: "new_name".to_string(),
            secret: "NEWSECRET".to_string(),
            issuer: "NEW_ISSUER".to_string(),
            period: 19,
            digits: 7,
            algorithm: Algorithm::SHA512,
            note: Some("Updated Note".to_string()),
            entry_type: AuthenticatorEntryType::Totp,
        };

        entry.update(update_params.clone()).expect("Should be able to update");

        assert_eq!(original_id, entry.id);
        assert_eq!(update_params.note, entry.note);

        if let AuthenticatorEntryContent::Totp(totp) = entry.content {
            assert_eq!(update_params.algorithm, totp.get_algorithm());
            assert_eq!(update_params.digits, totp.get_digits());
            assert_eq!(update_params.period, totp.get_period());
            assert_eq!(update_params.secret, totp.secret);
            assert_eq!(update_params.issuer, totp.issuer.unwrap());
            assert_eq!(update_params.name, totp.label.unwrap());
        } else {
            panic!("Should be a TOTP entry");
        }
    }

    #[test]
    fn can_update_steam_entry() {
        let mut entry = AuthenticatorEntry::new_steam_entry_from_params(AuthenticatorEntrySteamCreateParameters {
            name: "original_name".to_string(),
            secret: "J5GEIX2TIVBVERKU".to_string(),
            note: Some("original_note".to_string()),
        })
        .unwrap();

        let original_id = entry.id.clone();

        let update_params = AuthenticatorEntryUpdateContents {
            name: "new_name".to_string(),
            secret: "JZCVOX2TIVBVERKU".to_string(),
            note: Some("Updated Note".to_string()),
            entry_type: AuthenticatorEntryType::Steam,

            // Rest of the fields will be ignored
            issuer: "".to_string(),
            period: 0,                    // ignored
            digits: 0,                    // ignored
            algorithm: Algorithm::SHA512, // ignored
        };

        entry.update(update_params.clone()).expect("Should be able to update");

        assert_eq!(original_id, entry.id);
        assert_eq!(update_params.note, entry.note);

        if let AuthenticatorEntryContent::Steam(steam) = entry.content {
            assert_eq!(update_params.secret, steam.secret());
            assert_eq!(update_params.name, steam.name());
        } else {
            panic!("Should be a Steam entry");
        }
    }

    #[test]
    fn can_go_from_steam_to_totp() {
        let mut entry = AuthenticatorEntry::new_steam_entry_from_params(AuthenticatorEntrySteamCreateParameters {
            name: "original_name".to_string(),
            secret: "J5GEIX2TIVBVERKU".to_string(),
            note: Some("original_note".to_string()),
        })
        .unwrap();

        let original_id = entry.id.clone();

        let update_params = AuthenticatorEntryUpdateContents {
            name: "new_name".to_string(),
            secret: "JZCVOX2TIVBVERKU".to_string(),
            note: Some("Updated Note".to_string()),
            entry_type: AuthenticatorEntryType::Totp,
            issuer: "NEW_ISSUER".to_string(),
            period: 25,
            digits: 4,
            algorithm: Algorithm::SHA512,
        };

        entry.update(update_params.clone()).expect("Should be able to update");

        assert_eq!(original_id, entry.id);
        assert_eq!(update_params.note, entry.note);

        if let AuthenticatorEntryContent::Totp(totp) = entry.content {
            assert_eq!(update_params.algorithm, totp.get_algorithm());
            assert_eq!(update_params.digits, totp.get_digits());
            assert_eq!(update_params.period, totp.get_period());
            assert_eq!(update_params.secret, totp.secret);
            assert_eq!(update_params.issuer, totp.issuer.unwrap());
            assert_eq!(update_params.name, totp.label.unwrap());
        } else {
            panic!("Should be a TOTP entry");
        }
    }

    #[test]
    fn can_go_from_totp_to_steam() {
        let mut entry = AuthenticatorEntry::from_uri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA1&digits=8&period=15",
            Some("a note".to_string()),
        )
        .unwrap();

        let original_id = entry.id.clone();
        let update_params = AuthenticatorEntryUpdateContents {
            name: "new_name".to_string(),
            secret: "JZCVOX2TIVBVERKU".to_string(),
            note: Some("Updated Note".to_string()),
            entry_type: AuthenticatorEntryType::Steam,

            // Rest of the fields will be ignored
            issuer: "".to_string(),
            period: 0,                    // ignored
            digits: 0,                    // ignored
            algorithm: Algorithm::SHA512, // ignored
        };

        entry.update(update_params.clone()).expect("Should be able to update");

        assert_eq!(original_id, entry.id);
        assert_eq!(update_params.note, entry.note);

        if let AuthenticatorEntryContent::Steam(steam) = entry.content {
            assert_eq!(update_params.secret, steam.secret());
            assert_eq!(update_params.name, steam.name());
        } else {
            panic!("Should be a Steam entry");
        }
    }
}
