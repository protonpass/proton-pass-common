use proton_pass_common::duplicate::{DuplicateItemGroup, ItemForDuplicateDetection, find_duplicate_items};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
pub struct WasmItemsForDuplicateDetection(pub Vec<ItemForDuplicateDetection>);

#[derive(Tsify, Deserialize, Serialize)]
pub struct WasmDuplicateItemGroups(pub Vec<DuplicateItemGroup>);

#[wasm_bindgen]
pub fn find_duplicate_items_wasm(
    items: Ts<WasmItemsForDuplicateDetection>,
) -> Result<Ts<WasmDuplicateItemGroups>, JsError> {
    let items = items.to_rust()?.0;
    Ok(WasmDuplicateItemGroups(find_duplicate_items(items)).into_ts()?)
}
