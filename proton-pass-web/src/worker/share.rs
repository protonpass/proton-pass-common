use proton_pass_common::share::{visible_share_ids, Share};
use wasm_bindgen::prelude::*;

// Re-export core types that now have wasm bindings

#[wasm_bindgen]
pub fn get_visible_shares(shares: Vec<Share>, filter_hidden: bool) -> Vec<String> {
    visible_share_ids(&shares, filter_hidden)
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}
