use super::gen::authenticator_entry as proto;
use crate::steam::SteamTotp;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent, AuthenticatorEntryError};
use protobuf::Message;
use proton_pass_totp::totp::TOTP;

impl From<AuthenticatorEntryContent> for proto::AuthenticatorEntryContent {
    fn from(content: AuthenticatorEntryContent) -> Self {
        match content {
            AuthenticatorEntryContent::Steam(steam) => proto::AuthenticatorEntryContent {
                content: Some(proto::authenticator_entry_content::Content::Steam(
                    proto::AuthenticatorEntryContentSteam {
                        secret: steam.secret(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
            AuthenticatorEntryContent::Totp(totp) => proto::AuthenticatorEntryContent {
                content: Some(proto::authenticator_entry_content::Content::Totp(
                    proto::AuthenticatorEntryContentTotp {
                        uri: totp.to_uri(totp.label.clone(), totp.issuer.clone()),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        }
    }
}

impl From<AuthenticatorEntry> for proto::AuthenticatorEntry {
    fn from(entry: AuthenticatorEntry) -> Self {
        Self {
            metadata: protobuf::MessageField::some(proto::AuthenticatorEntryMetadata {
                note: match entry.note {
                    Some(ref n) => n.to_string(),
                    None => "".to_string(),
                },
                name: entry.name(),
                ..Default::default()
            }),
            content: protobuf::MessageField::some(entry.content.into()),
            ..Default::default()
        }
    }
}

impl TryFrom<proto::AuthenticatorEntry> for AuthenticatorEntry {
    type Error = AuthenticatorEntryError;
    fn try_from(entry: proto::AuthenticatorEntry) -> Result<Self, Self::Error> {
        let metadata = entry.metadata;
        Ok(Self {
            content: match entry.content.content {
                Some(ref content) => match content {
                    proto::authenticator_entry_content::Content::Totp(totp) => match TOTP::from_uri(&totp.uri) {
                        Ok(totp) => AuthenticatorEntryContent::Totp(totp),
                        Err(e) => {
                            return Err(AuthenticatorEntryError::SerializationError(format!(
                                "error parsing TOTP uri [{}]: {:?}",
                                totp.uri, e
                            )));
                        }
                    },
                    proto::authenticator_entry_content::Content::Steam(steam) => match SteamTotp::new(&steam.secret) {
                        Ok(mut steam) => {
                            if !metadata.name.is_empty() {
                                steam.name = Some(metadata.name.to_string())
                            }

                            AuthenticatorEntryContent::Steam(steam)
                        }
                        Err(e) => {
                            return Err(AuthenticatorEntryError::SerializationError(format!(
                                "error parsing Steam uri: {:?}",
                                e
                            )));
                        }
                    },
                },
                None => {
                    return Err(AuthenticatorEntryError::SerializationError(
                        "Entry content has no value".to_string(),
                    ));
                }
            },
            note: if metadata.note.is_empty() {
                None
            } else {
                Some(metadata.note.to_string())
            },
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
