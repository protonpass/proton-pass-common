use crate::entry::WasmAuthenticatorEntryModel;
use proton_authenticator::ordering::{reorder_items, EntryWithOrder};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct AuthenticatorEntryWithOrder {
    pub entry: WasmAuthenticatorEntryModel,
    pub modify_time: i64,
    pub order: i32,
}

impl TryFrom<AuthenticatorEntryWithOrder> for EntryWithOrder {
    type Error = JsError;

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
            entry: WasmAuthenticatorEntryModel::from(value.entry),
            modify_time: value.modify_time,
            order: value.order,
        }
    }
}

#[wasm_bindgen]
pub fn sort_entries(
    local: Vec<AuthenticatorEntryWithOrder>,
    remote: Vec<AuthenticatorEntryWithOrder>,
) -> Result<Vec<AuthenticatorEntryWithOrder>, JsError> {
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
