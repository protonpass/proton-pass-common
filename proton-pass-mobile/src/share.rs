use proton_pass_common::share::{visible_share_ids, Share as CommonShare, TargetType as CommonTargetType};

// START MAPPING TYPES

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetType {
    Vault,
    Item,
}

impl From<CommonTargetType> for TargetType {
    fn from(t: CommonTargetType) -> Self {
        match t {
            CommonTargetType::Vault => Self::Vault,
            CommonTargetType::Item => Self::Item,
            CommonTargetType::Folder => Self::Item, // Map Folder to Item for mobile
        }
    }
}

impl From<TargetType> for CommonTargetType {
    fn from(t: TargetType) -> Self {
        match t {
            TargetType::Vault => Self::Vault,
            TargetType::Item => Self::Item,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Share {
    pub share_id: String,
    pub vault_id: String,
    pub target_type: TargetType,
    pub target_id: String,
    pub role_id: String,
    pub permissions: u16,
}

impl From<CommonShare> for Share {
    fn from(s: CommonShare) -> Self {
        Self {
            share_id: s.share_id,
            vault_id: s.vault_id,
            target_type: TargetType::from(s.target_type),
            target_id: s.target_id,
            role_id: s.role,
            permissions: s.permissions,
        }
    }
}

impl From<Share> for CommonShare {
    fn from(s: Share) -> Self {
        Self {
            share_id: s.share_id,
            vault_id: s.vault_id,
            target_type: CommonTargetType::from(s.target_type),
            target_id: s.target_id,
            role: s.role_id,
            permissions: s.permissions,
        }
    }
}

// END MAPPING TYPES

pub struct ShareOverrideCalculator;

impl ShareOverrideCalculator {
    pub fn new() -> Self {
        Self
    }

    pub fn get_visible_shares(&self, shares: Vec<Share>) -> Vec<String> {
        let common_shares: Vec<CommonShare> = shares.into_iter().map(CommonShare::from).collect();
        visible_share_ids(&common_shares)
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }
}
