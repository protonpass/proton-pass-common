use proton_pass_common::share::{
    Share as CommonShare, TargetType as CommonTargetType, visible_share_ids,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize, Clone, Debug)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum TargetType {
    Vault,
    Item,
    Folder,
}

impl From<TargetType> for CommonTargetType {
    fn from(value: TargetType) -> Self {
        match value {
            TargetType::Vault => CommonTargetType::Vault,
            TargetType::Item => CommonTargetType::Item,
            TargetType::Folder => CommonTargetType::Folder,
        }
    }
}

#[derive(Tsify, Deserialize, Serialize, Clone, Debug)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Share {
    pub share_id: String,
    pub vault_id: String,
    pub target_type: TargetType,
    pub target_id: String,
    pub role: String,
    pub permissions: u16,
}

impl From<Share> for CommonShare {
    fn from(value: Share) -> Self {
        Self {
            share_id: value.share_id,
            vault_id: value.vault_id,
            target_type: CommonTargetType::from(value.target_type),
            target_id: value.target_id,
            role: value.role,
            permissions: value.permissions,
        }
    }
}

#[wasm_bindgen]
pub fn get_visible_shares(shares: Vec<Share>) -> Vec<String> {
    let common_shares: Vec<CommonShare> = shares.into_iter().map(CommonShare::from).collect();
    visible_share_ids(&common_shares)
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}

