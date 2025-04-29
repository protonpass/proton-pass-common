use crate::entry::WasmAuthenticatorEntryModel;
use crate::worker::JsResult;
use proton_authenticator::operations::{
    AuthenticatorEntryState as CommonEntryState, AuthenticatorOperation, EntryOperation as CommonEntryOperation,
    LocalEntry as CommonLocalEntry, RemoteEntry as CommonRemoteEntry,
};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmLocalEntryState {
    Synced,
    PendingSync,
    PendingToDelete,
}

impl From<WasmLocalEntryState> for CommonEntryState {
    fn from(value: WasmLocalEntryState) -> Self {
        match value {
            WasmLocalEntryState::Synced => CommonEntryState::Synced,
            WasmLocalEntryState::PendingSync => CommonEntryState::PendingSync,
            WasmLocalEntryState::PendingToDelete => CommonEntryState::PendingToDelete,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmLocalEntry {
    pub entry: WasmAuthenticatorEntryModel,
    pub state: WasmLocalEntryState,
}

impl TryFrom<WasmLocalEntry> for CommonLocalEntry {
    type Error = JsError;

    fn try_from(value: WasmLocalEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            entry: value.entry.to_entry()?,
            state: CommonEntryState::from(value.state),
        })
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmRemoteEntry {
    pub remote_id: String,
    pub entry: WasmAuthenticatorEntryModel,
}

impl TryFrom<WasmRemoteEntry> for CommonRemoteEntry {
    type Error = JsError;

    fn try_from(value: WasmRemoteEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            remote_id: value.remote_id,
            entry: value.entry.to_entry()?,
        })
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmOperationType {
    Upsert,
    DeleteLocal,
    DeleteLocalAndRemote,
    Push,
    Conflict,
}

impl From<AuthenticatorOperation> for WasmOperationType {
    fn from(value: AuthenticatorOperation) -> Self {
        match value {
            AuthenticatorOperation::Upsert => WasmOperationType::Upsert,
            AuthenticatorOperation::DeleteLocal => WasmOperationType::DeleteLocal,
            AuthenticatorOperation::DeleteLocalAndRemote => WasmOperationType::DeleteLocalAndRemote,
            AuthenticatorOperation::Push => WasmOperationType::Push,
            AuthenticatorOperation::Conflict => WasmOperationType::Conflict,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmEntryOperation {
    pub remote_id: Option<String>,
    pub entry: WasmAuthenticatorEntryModel,
    pub operation: WasmOperationType,
}

impl From<CommonEntryOperation> for WasmEntryOperation {
    fn from(value: CommonEntryOperation) -> Self {
        Self {
            remote_id: value.remote_id,
            entry: WasmAuthenticatorEntryModel::from(value.entry),
            operation: WasmOperationType::from(value.operation),
        }
    }
}

#[wasm_bindgen]
pub fn calculate_operations(
    remote: Vec<WasmRemoteEntry>,
    local: Vec<WasmLocalEntry>,
) -> JsResult<Vec<WasmEntryOperation>> {
    let mut remote_mapped = Vec::with_capacity(remote.len());
    for remote_entry in remote {
        remote_mapped.push(CommonRemoteEntry::try_from(remote_entry)?);
    }

    let mut local_mapped = Vec::with_capacity(local.len());
    for local_entry in local {
        local_mapped.push(CommonLocalEntry::try_from(local_entry)?);
    }

    let ops = proton_authenticator::operations::calculate_operations_to_perform(remote_mapped, local_mapped);
    let mut result: Vec<WasmEntryOperation> = Vec::new();
    for op in ops {
        result.push(WasmEntryOperation::from(op));
    }

    Ok(result)
}
