/*
 *  Copyright (c) 2026 Proton AG
 *  This file is part of Proton AG and Proton Pass.
 *
 *  Proton Pass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Proton Pass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Proton Pass.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

use proton_pass_common::merge::{
    GroupMergePlan, ItemForMerge, MergeError, MergePlan, plan_group_merge, plan_item_merge,
};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
pub struct WasmItemForMergeParams {
    pub primary: ItemForMerge,
    pub secondary: ItemForMerge,
}

#[derive(Tsify, Deserialize, Serialize)]
pub struct WasmItemForMergeGroupParams {
    pub primary: ItemForMerge,
    pub secondaries: Vec<ItemForMerge>,
}

#[derive(Tsify, Deserialize, Serialize)]
pub struct WasmMergePlan(pub MergePlan);

#[derive(Tsify, Deserialize, Serialize)]
pub struct WasmGroupMergePlan(pub GroupMergePlan);

fn to_js_error(error: MergeError) -> JsError {
    JsError::new(&error.to_string())
}

/// Plans merging `secondary` into `primary`. The plan carries both the per-field decisions
/// (for display) and the resulting merged item (for persisting the update).
#[wasm_bindgen]
pub fn plan_item_merge_wasm(params: Ts<WasmItemForMergeParams>) -> Result<Ts<WasmMergePlan>, JsError> {
    let params = params.to_rust()?;
    let plan = plan_item_merge(&params.primary, &params.secondary).map_err(to_js_error)?;
    Ok(WasmMergePlan(plan).into_ts()?)
}

/// Plans merging a whole group: `secondaries` are folded into `primary` in the given (visual)
/// order. The result describes one batch update of the primary followed by trashing the
/// secondaries, which callers can execute as a single commit.
#[wasm_bindgen]
pub fn plan_group_merge_wasm(params: Ts<WasmItemForMergeGroupParams>) -> Result<Ts<WasmGroupMergePlan>, JsError> {
    let params = params.to_rust()?;
    let plan = plan_group_merge(&params.primary, &params.secondaries).map_err(to_js_error)?;
    Ok(WasmGroupMergePlan(plan).into_ts()?)
}
