use credential_exchange_format::Credential;

use super::CxfCredential;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CxfCredentialKind {
    Address,
    ApiKey,
    BasicAuth,
    CreditCard,
    CustomFields,
    DriversLicense,
    IdentityDocument,
    Note,
    Passkey,
    Passport,
    PersonName,
    SshKey,
    Totp,
    Wifi,
    Other,
}

impl CxfCredentialKind {
    pub(crate) fn of(credential: &CxfCredential) -> Self {
        match credential {
            Credential::Address(_) => Self::Address,
            Credential::ApiKey(_) => Self::ApiKey,
            Credential::BasicAuth(_) => Self::BasicAuth,
            Credential::CreditCard(_) => Self::CreditCard,
            Credential::CustomFields(_) => Self::CustomFields,
            Credential::DriversLicense(_) => Self::DriversLicense,
            Credential::IdentityDocument(_) => Self::IdentityDocument,
            Credential::Note(_) => Self::Note,
            Credential::Passkey(_) => Self::Passkey,
            Credential::Passport(_) => Self::Passport,
            Credential::PersonName(_) => Self::PersonName,
            Credential::SshKey(_) => Self::SshKey,
            Credential::Totp(_) => Self::Totp,
            Credential::Wifi(_) => Self::Wifi,
            Credential::File(_)
            | Credential::GeneratedPassword(_)
            | Credential::ItemReference(_)
            | Credential::Unknown { .. } => Self::Other,
            _ => Self::Other,
        }
    }
}
