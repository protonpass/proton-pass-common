use crate::{AuthenticatorEntryModel, AuthenticatorError};
use proton_authenticator::ordering::{reorder_items, EntryWithOrder};

#[derive(uniffi::Record)]
pub struct AuthenticatorEntryWithOrder {
    pub entry: AuthenticatorEntryModel,
    pub modify_time: i64,
    pub order: i32,
}

impl TryFrom<AuthenticatorEntryWithOrder> for EntryWithOrder {
    type Error = AuthenticatorError;

    fn try_from(value: AuthenticatorEntryWithOrder) -> Result<Self, Self::Error> {
        let as_entry = value.entry.to_entry()?;
        Ok(Self {
            entry: as_entry,
            modify_time: value.modify_time,
            order: value.order,
        })
    }
}

impl From<EntryWithOrder> for AuthenticatorEntryWithOrder {
    fn from(value: EntryWithOrder) -> Self {
        Self {
            entry: AuthenticatorEntryModel::from(value.entry),
            modify_time: value.modify_time,
            order: value.order,
        }
    }
}

#[derive(uniffi::Object)]
pub struct AuthenticatorEntrySorter;

#[uniffi::export]
impl AuthenticatorEntrySorter {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn sort(
        &self,
        local: Vec<AuthenticatorEntryWithOrder>,
        remote: Vec<AuthenticatorEntryWithOrder>,
    ) -> Result<Vec<AuthenticatorEntryWithOrder>, AuthenticatorError> {
        let mut local_mapped = vec![];
        for entry in local {
            local_mapped.push(EntryWithOrder::try_from(entry)?);
        }
        let mut remote_mapped = vec![];
        for entry in remote {
            remote_mapped.push(EntryWithOrder::try_from(entry)?);
        }

        let res = reorder_items(&local_mapped, &remote_mapped);

        let mut res_mapped = Vec::new();
        for entry in res {
            res_mapped.push(AuthenticatorEntryWithOrder::from(entry));
        }

        Ok(res_mapped)
    }
}
