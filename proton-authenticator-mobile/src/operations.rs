use crate::{AuthenticatorEntryModel, AuthenticatorError};
use proton_authenticator::operations::{
    AuthenticatorEntryState as CommonEntryState, AuthenticatorOperation, EntryOperation as CommonEntryOperation,
    LocalEntry as CommonLocalEntry, RemoteEntry as CommonRemoteEntry,
};

pub enum LocalEntryState {
    Synced,
    PendingSync,
    PendingToDelete,
}

impl From<LocalEntryState> for CommonEntryState {
    fn from(value: LocalEntryState) -> Self {
        match value {
            LocalEntryState::Synced => CommonEntryState::Synced,
            LocalEntryState::PendingSync => CommonEntryState::PendingSync,
            LocalEntryState::PendingToDelete => CommonEntryState::PendingToDelete,
        }
    }
}

pub struct LocalEntry {
    pub entry: AuthenticatorEntryModel,
    pub state: LocalEntryState,
    pub modify_time: i64,
    pub local_modify_time: Option<i64>,
}

impl TryFrom<LocalEntry> for CommonLocalEntry {
    type Error = AuthenticatorError;

    fn try_from(value: LocalEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            entry: value.entry.to_entry()?,
            state: CommonEntryState::from(value.state),
            modify_time: value.modify_time,
            local_modify_time: value.local_modify_time,
        })
    }
}

pub struct RemoteEntry {
    pub remote_id: String,
    pub revision: u32,
    pub entry: AuthenticatorEntryModel,
    pub modify_time: i64,
}

impl TryFrom<RemoteEntry> for CommonRemoteEntry {
    type Error = AuthenticatorError;

    fn try_from(value: RemoteEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            remote_id: value.remote_id,
            revision: value.revision,
            entry: value.entry.to_entry()?,
            modify_time: value.modify_time,
        })
    }
}

pub enum OperationType {
    Upsert,
    DeleteLocal,
    DeleteLocalAndRemote,
    Push,
}

impl From<AuthenticatorOperation> for OperationType {
    fn from(value: AuthenticatorOperation) -> Self {
        match value {
            AuthenticatorOperation::Upsert => OperationType::Upsert,
            AuthenticatorOperation::DeleteLocal => OperationType::DeleteLocal,
            AuthenticatorOperation::DeleteLocalAndRemote => OperationType::DeleteLocalAndRemote,
            AuthenticatorOperation::Push => OperationType::Push,
        }
    }
}

pub struct EntryOperation {
    pub remote_id: Option<String>,
    pub revision: Option<u32>,
    pub entry: AuthenticatorEntryModel,
    pub operation: OperationType,
}

impl From<CommonEntryOperation> for EntryOperation {
    fn from(value: CommonEntryOperation) -> Self {
        Self {
            remote_id: value.remote_id,
            revision: value.revision,
            entry: AuthenticatorEntryModel::from(value.entry),
            operation: OperationType::from(value.operation),
        }
    }
}

pub struct SyncOperationChecker;

impl SyncOperationChecker {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate_operations(
        &self,
        remote: Vec<RemoteEntry>,
        local: Vec<LocalEntry>,
    ) -> Result<Vec<EntryOperation>, AuthenticatorError> {
        let mut remote_mapped = Vec::with_capacity(remote.len());
        for remote_entry in remote {
            remote_mapped.push(CommonRemoteEntry::try_from(remote_entry)?);
        }

        let mut local_mapped = Vec::with_capacity(local.len());
        for local_entry in local {
            local_mapped.push(CommonLocalEntry::try_from(local_entry)?);
        }

        let ops = proton_authenticator::operations::calculate_operations_to_perform(remote_mapped, local_mapped);
        let mut result: Vec<EntryOperation> = Vec::new();
        for op in ops {
            result.push(EntryOperation::from(op));
        }

        Ok(result)
    }
}
