use proton_pass_common::share::{visible_share_ids, Share as CommonShare, TargetType as CommonTargetType};

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
    pub flags: u16,
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
            flags: s.flags,
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
            flags: s.flags,
        }
    }
}

pub struct ShareOverrideCalculator;

impl ShareOverrideCalculator {
    pub fn new() -> Self {
        Self
    }

    pub fn get_visible_shares(&self, shares: Vec<Share>, filter_hidden: bool) -> Vec<String> {
        let common_shares: Vec<CommonShare> = shares.into_iter().map(CommonShare::from).collect();
        visible_share_ids(&common_shares, filter_hidden)
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }
}
