use proton_pass_derive::ffi_type;
use std::collections::{HashMap, HashSet};

#[ffi_type]
#[derive(Debug, Clone)]
pub struct Share {
    pub share_id: String,
    pub vault_id: String,
    pub target_type: TargetType,
    pub target_id: String,
    pub role: String,
    pub permissions: u16,
    pub flags: u16,
    pub user_is_vault_owner: bool,
    pub is_group_share: bool,
    pub create_time: u32,
}

#[ffi_type]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TargetType {
    Vault,
    Item,
}

const ROLE_MANAGER: &str = "1";
const ROLE_WRITE: &str = "2";
const ROLE_READ: &str = "3";

const FLAG_HIDDEN: u16 = 0x1;

fn role_priority(role: &str) -> u8 {
    match role.to_ascii_uppercase().as_str() {
        ROLE_MANAGER => 3,
        ROLE_WRITE => 2,
        ROLE_READ => 1,
        _ => 0,
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct ShareTriplet<'a> {
    vault_id: &'a str,
    target_type: &'a TargetType,
    target_id: &'a str,
}

pub fn visible_share_ids(shares: &[Share], filter_hidden: bool) -> Vec<&str> {
    // Deduplicate per (vault_id, target_type, target_id)
    let mut best_per_triplet: HashMap<ShareTriplet, &Share> = HashMap::new();
    let mut hidden_vaults: HashSet<&str> = HashSet::new();

    if filter_hidden {
        for share in shares {
            if (share.flags & FLAG_HIDDEN) == FLAG_HIDDEN {
                hidden_vaults.insert(&share.vault_id);
            }
        }
    }

    for share in shares {
        if hidden_vaults.contains(&share.vault_id.as_str()) {
            continue;
        }
        let key = ShareTriplet {
            vault_id: &share.vault_id,
            target_type: &share.target_type,
            target_id: &share.target_id,
        };
        best_per_triplet
            .entry(key)
            .and_modify(|existing| {
                //We always give priority to the share of the owner of the vault
                if share.user_is_vault_owner {
                    *existing = share;
                    return;
                }
                let share_role_prio = role_priority(&share.role);
                let existing_role_prio = role_priority(&existing.role);
                if share_role_prio > existing_role_prio {
                    //If the share has higher prio we just keep it
                    *existing = share;
                    return;
                }
                if share_role_prio == existing_role_prio {
                    if existing.is_group_share && !share.is_group_share {
                        // If the exiting is a group one but the new one is not, keep the new one
                        *existing = share;
                    }
                    if share.create_time < existing.create_time {
                        // If it's an older share keep it
                        *existing = share;
                    }
                }
            })
            .or_insert_with(|| share);
    }

    // Build lookup by vault_id for vault shares
    let mut vault_role_priorities: HashMap<&String, u8> = HashMap::new();
    for share in best_per_triplet.values() {
        if share.target_type == TargetType::Vault {
            vault_role_priorities.insert(&share.vault_id, role_priority(&share.role));
        }
    }

    // Apply vault vs non-vault visibility rules
    let mut visible: Vec<&str> = Vec::new();

    for share in best_per_triplet.values() {
        if share.target_type == TargetType::Vault {
            // Always keep vault shares
            visible.push(&share.share_id);
        } else if let Some(&vault_role_prio) = vault_role_priorities.get(&share.vault_id) {
            let share_role_prio = role_priority(&share.role);
            if share_role_prio > vault_role_prio {
                // Keep if share has more permissions
                visible.push(&share.share_id);
            }
            // Otherwise skip (hidden by higher vault)
        } else {
            // No parent vault there. Keep it
            visible.push(&share.share_id);
        }
    }

    visible
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ShareBuilder {
        share_id: String,
        vault_id: String,
        target_type: TargetType,
        target_id: String,
        role: String,
        permissions: u16,
        flags: u16,
        user_is_vault_owner: bool,
        is_group_share: bool,
        create_time: u32,
    }

    impl ShareBuilder {
        fn new() -> Self {
            Self {
                share_id: "share".to_owned(),
                vault_id: "v".to_owned(),
                target_type: TargetType::Vault,
                target_id: "1".to_owned(),
                role: ROLE_READ.to_string(),
                permissions: 0,
                flags: 0,
                create_time: 0,
                user_is_vault_owner: false,
                is_group_share: false,
            }
        }

        fn share_id(mut self, id: &str) -> Self {
            self.share_id = id.to_owned();
            self
        }

        fn vault_id(mut self, id: &str) -> Self {
            self.vault_id = id.to_owned();
            self
        }

        fn target_type(mut self, t: TargetType) -> Self {
            self.target_type = t;
            self
        }

        fn target_id(mut self, id: &str) -> Self {
            self.target_id = id.to_owned();
            self
        }

        fn role(mut self, r: &str) -> Self {
            self.role = r.to_owned();
            self
        }

        fn flags(mut self, f: u16) -> Self {
            self.flags = f;
            self
        }

        fn create_time(mut self, t: u16) -> Self {
            self.create_time = t;
            self
        }

        fn vault_owner(mut self) -> Self {
            self.user_is_vault_owner = true;
            self
        }

        fn group_share(mut self) -> Self {
            self.is_group_share = true;
            self
        }

        fn build(self) -> Share {
            Share {
                share_id: self.share_id,
                vault_id: self.vault_id,
                target_type: self.target_type,
                target_id: self.target_id,
                role: self.role,
                permissions: self.permissions,
                flags: self.flags,
                user_is_vault_owner: self.user_is_vault_owner,
                is_group_share: self.is_group_share,
                create_time: self.create_time,
            }
        }
    }

    fn share_builder() -> ShareBuilder {
        ShareBuilder::new()
    }

    fn assert_contains(out: &[&str], share_id: &str) {
        assert_eq!(1, out.iter().filter(|id| (**id).eq(share_id)).count());
    }

    #[test]
    fn test_empty_list() {
        let out = visible_share_ids(&[], false);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn test_simple_return_for_all_types() {
        for target_type in [TargetType::Vault, TargetType::Item] {
            let s = share_builder().target_type(target_type).build();
            let shares = [s];
            let out = visible_share_ids(&shares, false);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0], shares[0].share_id);
        }
    }

    #[test]
    fn test_disabled_filter_hidden_works() {
        // When filter_hidden is false, the hidden flag has no effect.
        // The manager share (hidden) wins over the read share (visible) on role priority.
        for target_type in [TargetType::Vault, TargetType::Item] {
            let s_visible = share_builder()
                .share_id("sv")
                .target_type(target_type.clone())
                .role(ROLE_READ)
                .build();
            let s_hidden = share_builder()
                .share_id("sh")
                .target_type(target_type.clone())
                .role(ROLE_MANAGER)
                .flags(FLAG_HIDDEN)
                .build();
            let hidden_share_id = s_hidden.share_id.clone();
            let shares = [s_visible, s_hidden];
            let out = visible_share_ids(&shares, false);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0], hidden_share_id);
        }
    }

    #[test]
    fn test_hidden_matches_all_shares_for_vault() {
        // When a vault has a hidden share, all shares in that vault are filtered out.
        for target_type in [TargetType::Vault, TargetType::Item] {
            let s_hidden = share_builder()
                .share_id("sh")
                .vault_id("v1")
                .target_type(target_type.clone())
                .role(ROLE_MANAGER)
                .flags(FLAG_HIDDEN)
                .build();
            let s_visible = share_builder()
                .share_id("sv")
                .vault_id("v1")
                .target_type(target_type.clone())
                .role(ROLE_READ)
                .build();
            let s_other = share_builder()
                .share_id("so")
                .vault_id("v2")
                .target_type(target_type.clone())
                .role(ROLE_READ)
                .build();
            let other_share_id = s_other.share_id.clone();
            let shares = [s_visible, s_hidden, s_other];
            let out = visible_share_ids(&shares, true);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0], other_share_id);
        }
    }

    #[test]
    fn test_hidden_matches_items_in_vault() {
        // A hidden vault share causes all items in that vault to be hidden too.
        let vault_hidden = share_builder()
            .share_id("sh")
            .vault_id("v1")
            .target_type(TargetType::Vault)
            .role(ROLE_MANAGER)
            .flags(FLAG_HIDDEN)
            .build();
        let item_in_hidden_vault = share_builder()
            .share_id("sv")
            .vault_id("v1")
            .target_type(TargetType::Item)
            .target_id("32")
            .role(ROLE_READ)
            .build();
        let item_in_other_vault = share_builder()
            .share_id("so")
            .vault_id("v2")
            .target_type(TargetType::Item)
            .role(ROLE_READ)
            .build();
        let other_share_id = item_in_other_vault.share_id.clone();
        let shares = [vault_hidden, item_in_hidden_vault, item_in_other_vault];
        let out = visible_share_ids(&shares, true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], other_share_id);
    }

    #[test]
    fn test_shadow_target_with_worse_role() {
        // Only the highest-role share per (vault, target_type, target_id) is kept.
        for target_type in [TargetType::Vault, TargetType::Item] {
            let role_tests = [
                (ROLE_MANAGER, ROLE_WRITE),
                (ROLE_MANAGER, ROLE_READ),
                (ROLE_WRITE, ROLE_READ),
            ];
            for (best_role, worse_role) in role_tests.iter() {
                let best_role_share = share_builder()
                    .share_id(&format!("a{:?}{}", &target_type, worse_role))
                    .target_type(target_type.clone())
                    .role(best_role)
                    .build();
                let worse_role_share = share_builder()
                    .share_id(&format!("b{:?}{}", &target_type, worse_role))
                    .target_type(target_type.clone())
                    .role(worse_role)
                    .build();
                let best_share_id = best_role_share.share_id.clone();
                let shares = [
                    worse_role_share.clone(),
                    best_role_share.clone(),
                    worse_role_share,
                    best_role_share,
                ];
                let out = visible_share_ids(&shares, false);
                assert_eq!(out.len(), 1);
                assert_eq!(out[0], best_share_id);
            }
        }
    }

    #[test]
    fn test_vault_masks_item_with_less_perms() {
        // An item share with equal or lower role than the vault share is hidden.
        let write_vault = share_builder()
            .share_id("vault_share")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_WRITE)
            .build();
        let read_item = share_builder()
            .share_id("item_read")
            .target_type(TargetType::Item)
            .role(ROLE_READ)
            .build();
        let write_item = share_builder()
            .share_id("item_write")
            .target_type(TargetType::Item)
            .role(ROLE_WRITE)
            .build();
        let share_id_to_keep = write_vault.share_id.clone();
        let shares = [write_vault, write_item, read_item];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], share_id_to_keep);
    }

    #[test]
    fn test_vault_masks_item_with_more_perms() {
        // An item share with a higher role than the vault share is kept alongside the vault share.
        let read_vault = share_builder()
            .share_id("vault_share")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_READ)
            .build();
        let read_item = share_builder()
            .share_id("item_read")
            .target_type(TargetType::Item)
            .role(ROLE_READ)
            .build();
        let write_item = share_builder()
            .share_id("item_write")
            .target_type(TargetType::Item)
            .role(ROLE_WRITE)
            .build();
        let vault_share_id = read_vault.share_id.clone();
        let item_share_id = write_item.share_id.clone();
        let shares = [read_vault, write_item, read_item];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 2);
        assert_contains(&out, &vault_share_id);
        assert_contains(&out, &item_share_id);
    }

    #[test]
    fn test_keep_items_in_other_vault() {
        // An item share in a different vault from any vault share is always kept.
        let vault = share_builder()
            .share_id("vault_share")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_MANAGER)
            .build();
        let item = share_builder()
            .share_id("item_read")
            .vault_id("v1")
            .target_type(TargetType::Item)
            .role(ROLE_READ)
            .build();
        let vault_share_id = vault.share_id.clone();
        let item_share_id = item.share_id.clone();
        let shares = [vault, item];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 2);
        assert_contains(&out, &vault_share_id);
        assert_contains(&out, &item_share_id);
    }

    #[test]
    fn test_mixed_vault_and_item_shares_are_kept_if_item_has_more_perms() {
        // vault_0_admin supersedes vault_0_write (same triplet, higher role).
        // item in v1 has no parent vault share, so it is kept.
        // item_2_write in v2 has same role as vault_2_write, so it is masked.
        let vault_0_admin = share_builder()
            .share_id("vault_share")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_MANAGER)
            .build();
        let vault_0_write = share_builder() // Superseded by vault_0_admin
            .share_id("vault_share")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_WRITE)
            .build();
        let item = share_builder() // Item in vault 1 that we don't have a vault share for
            .share_id("item_read")
            .vault_id("v1")
            .target_type(TargetType::Item)
            .role(ROLE_READ)
            .build();
        let vault_2_write = share_builder() // Only one share for this vault
            .share_id("vault_2_share")
            .vault_id("v2")
            .target_type(TargetType::Vault)
            .target_id("v2")
            .role(ROLE_WRITE)
            .build();
        let item_2_write = share_builder() // Same role as vault_2_write, so masked
            .share_id("item_2_write")
            .vault_id("v2")
            .target_type(TargetType::Item)
            .target_id("2")
            .role(ROLE_WRITE)
            .build();
        let shares_to_keep = [
            vault_0_admin.share_id.clone(),
            item.share_id.clone(),
            vault_2_write.share_id.clone(),
        ];
        let shares = [vault_2_write, vault_0_write, vault_0_admin, item, item_2_write];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), shares_to_keep.len());
        assert!(shares_to_keep.iter().all(|s| out.contains(&s.as_str())));
    }

    #[test]
    fn test_give_prio_to_vault_owner() {
        // The owner's share is kept even when another share has a higher role.
        let non_owner = share_builder()
            .share_id("non_owner_share")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_MANAGER)
            .build();
        let owner = share_builder()
            .share_id("owner_share")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_READ)
            .vault_owner()
            .build();
        let owner_share_id = owner.share_id.clone();
        let shares = [non_owner, owner];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], owner_share_id);
    }

    #[test]
    fn test_give_prio_to_non_group_shares() {
        // Among equal-role shares, the non-group share is preferred over group shares.
        let group_share_1 = share_builder()
            .share_id("group_share_1")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_MANAGER)
            .group_share()
            .build();
        let non_group_share = share_builder()
            .share_id("non_group_share")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_MANAGER)
            .build();
        let group_share_2 = share_builder()
            .share_id("group_share_2")
            .target_type(TargetType::Vault)
            .target_id("v0")
            .role(ROLE_MANAGER)
            .group_share()
            .build();
        let non_group_share_id = non_group_share.share_id.clone();
        let shares = [group_share_1, non_group_share, group_share_2];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], non_group_share_id);
    }

    #[test]
    fn test_give_prio_to_older_shares() {
        // Among equal-role shares, the non-group share is preferred over group shares.
        let newer = share_builder().share_id("newer").create_time(2).build();
        let older = share_builder().share_id("older").create_time(1).build();
        let older_share_id = older.share_id.clone();
        let shares = [newer, older];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], older_share_id);
    }
}
