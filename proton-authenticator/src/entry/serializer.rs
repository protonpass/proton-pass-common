use super::gen::authenticator_entry as proto;
use crate::steam::SteamTotp;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent, AuthenticatorEntryError};
use protobuf::Message;
use proton_pass_totp::totp::TOTP;

impl From<AuthenticatorEntryContent> for proto::AuthenticatorEntryContent {
    fn from(content: AuthenticatorEntryContent) -> Self {
        match content {
            AuthenticatorEntryContent::Steam(steam) => proto::AuthenticatorEntryContent {
                entry_type: protobuf::EnumOrUnknown::new(proto::AuthenticatorEntryType::STEAM),
                uri: steam.uri(),
                ..Default::default()
            },
            AuthenticatorEntryContent::Totp(totp) => proto::AuthenticatorEntryContent {
                entry_type: protobuf::EnumOrUnknown::new(proto::AuthenticatorEntryType::TOTP),
                uri: totp.to_uri(totp.label.clone(), totp.issuer.clone()),
                ..Default::default()
            },
        }
    }
}

impl From<AuthenticatorEntry> for proto::AuthenticatorEntry {
    fn from(entry: AuthenticatorEntry) -> Self {
        Self {
            content: protobuf::MessageField::some(entry.content.into()),
            note: match entry.note {
                Some(ref n) => n.to_string(),
                None => "".to_string(),
            },
            ..Default::default()
        }
    }
}

impl TryFrom<proto::AuthenticatorEntry> for AuthenticatorEntry {
    type Error = AuthenticatorEntryError;
    fn try_from(entry: proto::AuthenticatorEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            content: match entry.content.entry_type.enum_value() {
                Ok(entry_type) => match entry_type {
                    proto::AuthenticatorEntryType::TOTP => match TOTP::from_uri(entry.content.uri.as_str()) {
                        Ok(totp) => AuthenticatorEntryContent::Totp(totp),
                        Err(e) => {
                            return Err(AuthenticatorEntryError::SerializationError(format!(
                                "cannot parse totp uri: {:?}",
                                e
                            )))
                        }
                    },
                    proto::AuthenticatorEntryType::STEAM => match SteamTotp::new_from_uri(&entry.content.uri) {
                        Ok(steam) => AuthenticatorEntryContent::Steam(steam),
                        Err(e) => {
                            return Err(AuthenticatorEntryError::SerializationError(format!(
                                "cannot parse steam uri: {:?}",
                                e
                            )))
                        }
                    },
                },
                Err(e) => {
                    return Err(AuthenticatorEntryError::SerializationError(format!(
                        "unknown AuthenticatorEntryContent.value {e}"
                    )))
                }
            },
            note: if entry.note.is_empty() { None } else { Some(entry.note) },
        })
    }
}

pub fn serialize_entry(entry: AuthenticatorEntry) -> Result<Vec<u8>, protobuf::Error> {
    proto::AuthenticatorEntry::from(entry).write_to_bytes()
}

pub fn deserialize_entry(input: &[u8]) -> Result<AuthenticatorEntry, AuthenticatorEntryError> {
    let parsed = proto::AuthenticatorEntry::parse_from_bytes(input).map_err(|e| {
        AuthenticatorEntryError::SerializationError(format!("cannot parse AuthenticatorEntry from data: {:?}", e))
    })?;

    AuthenticatorEntry::try_from(parsed)
}
