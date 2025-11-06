use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Share {
    pub share_id: String,
    pub vault_id: String,
    pub target_type: TargetType,
    pub target_id: String,
    pub role: String,
    pub permissions: u16,
    pub flags: u16,
}

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
    let mut hidden_triplets: HashSet<ShareTriplet> = HashSet::new();

    if filter_hidden {
        for share in shares {
            if (share.flags & FLAG_HIDDEN) == FLAG_HIDDEN {
                hidden_triplets.insert(ShareTriplet {
                    vault_id: &share.vault_id,
                    target_type: &share.target_type,
                    target_id: &share.target_id,
                });
            }
        }
    }

    for share in shares {
        let key = ShareTriplet {
            vault_id: &share.vault_id,
            target_type: &share.target_type,
            target_id: &share.target_id,
        };
        if hidden_triplets.contains(&key) {
            continue;
        }
        best_per_triplet
            .entry(key)
            .and_modify(|existing| {
                let share_role_prio = role_priority(&share.role);
                let existing_role_prio = role_priority(&existing.role);
                if share_role_prio > existing_role_prio
                    || (share_role_prio == existing_role_prio && share.vault_id < existing.vault_id)
                {
                    *existing = share;
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

    #[test]
    fn test_empty_list() {
        let out = visible_share_ids(&[], false);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn test_simple_return_for_all_types() {
        for target_type in [TargetType::Vault, TargetType::Item] {
            let s = Share {
                share_id: "a".to_owned(),
                vault_id: "v".to_owned(),
                target_type,
                target_id: "1".to_owned(),
                role: ROLE_MANAGER.to_string(),
                permissions: 0,
                flags: 0,
            };
            let shares = [s];
            let out = visible_share_ids(&shares, false);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0], shares[0].share_id);
        }
    }

    #[test]
    fn test_disabled_filter_hidden_works() {
        for target_type in [TargetType::Vault, TargetType::Item] {
            let s_visible = Share {
                share_id: "sv".to_owned(),
                vault_id: "v".to_owned(),
                target_type: target_type.clone(),
                target_id: "1".to_owned(),
                role: ROLE_READ.to_string(),
                permissions: 0,
                flags: 0,
            };
            let s_hidden = Share {
                share_id: "sh".to_owned(),
                vault_id: "v".to_owned(),
                target_type: target_type.clone(),
                target_id: "1".to_owned(),
                role: ROLE_MANAGER.to_string(),
                permissions: 0,
                flags: FLAG_HIDDEN,
            };
            let hidden_share_id = s_hidden.share_id.clone();
            let shares = [s_visible, s_hidden];
            let out = visible_share_ids(&shares, false);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0], hidden_share_id);
        }
    }

    #[test]
    fn test_hidden_matches_all_triplets() {
        for target_type in [TargetType::Vault, TargetType::Item] {
            let s_hidden = Share {
                share_id: "sh".to_owned(),
                vault_id: "v".to_owned(),
                target_type: target_type.clone(),
                target_id: "1".to_owned(),
                role: ROLE_MANAGER.to_string(),
                permissions: 0,
                flags: FLAG_HIDDEN,
            };
            let s_visible = Share {
                share_id: "sv".to_owned(),
                vault_id: "v".to_owned(),
                target_type,
                target_id: "1".to_owned(),
                role: ROLE_READ.to_string(),
                permissions: 0,
                flags: 0,
            };
            let shares = [s_visible, s_hidden];
            let out = visible_share_ids(&shares, true);
            assert_eq!(out.len(), 0);
        }
    }

    #[test]
    fn test_shadow_target_with_worse_role() {
        for target_type in [TargetType::Vault, TargetType::Item] {
            let role_tests = [
                (ROLE_MANAGER, ROLE_WRITE),
                (ROLE_MANAGER, ROLE_READ),
                (ROLE_WRITE, ROLE_READ),
            ];
            for (best_role, worse_role) in role_tests.iter() {
                let best_role_share = Share {
                    share_id: format!("a{:?}{}", &target_type, worse_role),
                    vault_id: "v0".to_owned(),
                    target_type: target_type.clone(),
                    target_id: "1".to_owned(),
                    role: best_role.to_string(),
                    permissions: 0,
                    flags: 0,
                };
                let worse_role_share = Share {
                    share_id: format!("b{:?}{}", &target_type, worse_role),
                    vault_id: "v0".to_owned(),
                    target_type: target_type.clone(),
                    target_id: "1".to_owned(),
                    role: worse_role.to_string(),
                    permissions: 0,
                    flags: 0,
                };
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
        let write_vault = Share {
            share_id: "vault_share".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Vault,
            target_id: "v0".to_owned(),
            role: ROLE_WRITE.to_string(),
            permissions: 0,
            flags: 0,
        };
        let read_item = Share {
            share_id: "item_read".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Item,
            target_id: "1".to_owned(),
            role: ROLE_READ.to_string(),
            permissions: 0,
            flags: 0,
        };
        let write_item = Share {
            share_id: "item_write".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Item,
            target_id: "1".to_owned(),
            role: ROLE_WRITE.to_string(),
            permissions: 0,
            flags: 0,
        };
        let share_id_to_keep = write_vault.share_id.clone();
        let shares = [write_vault, write_item, read_item];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], share_id_to_keep);
    }

    #[test]
    fn test_vault_masks_item_with_more_perms() {
        let read_vault = Share {
            share_id: "vault_share".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Vault,
            target_id: "v0".to_owned(),
            role: ROLE_READ.to_string(),
            permissions: 0,
            flags: 0,
        };
        let read_item = Share {
            share_id: "item_read".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Item,
            target_id: "1".to_owned(),
            role: ROLE_READ.to_string(),
            permissions: 0,
            flags: 0,
        };
        let write_item = Share {
            share_id: "item_write".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Item,
            target_id: "1".to_owned(),
            role: ROLE_WRITE.to_string(),
            permissions: 0,
            flags: 0,
        };
        let vault_share_id = read_vault.share_id.clone();
        let item_share_id = write_item.share_id.clone();
        let shares = [read_vault, write_item, read_item];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 2);
        assert_eq!(1, out.iter().filter(|share_id| (*share_id).eq(&vault_share_id)).count());
        assert_eq!(1, out.iter().filter(|share_id| (*share_id).eq(&item_share_id)).count());
    }

    #[test]
    fn test_keep_items_in_other_vault() {
        let vault = Share {
            share_id: "vault_share".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Vault,
            target_id: "v0".to_owned(),
            role: ROLE_MANAGER.to_string(),
            permissions: 0,
            flags: 0,
        };
        let item = Share {
            share_id: "item_read".to_string(),
            vault_id: "v1".to_owned(),
            target_type: TargetType::Item,
            target_id: "1".to_owned(),
            role: ROLE_READ.to_string(),
            permissions: 0,
            flags: 0,
        };
        let vault_share_id = vault.share_id.clone();
        let item_share_id = item.share_id.clone();
        let shares = [vault, item];
        let out = visible_share_ids(&shares, false);
        assert_eq!(out.len(), 2);
        assert_eq!(1, out.iter().filter(|share_id| (*share_id).eq(&vault_share_id)).count());
        assert_eq!(1, out.iter().filter(|share_id| (*share_id).eq(&item_share_id)).count());
    }

    #[test]
    fn test_mixed_vault_and_item_shares_are_kept_if_item_has_more_perms() {
        let vault_0_admin = Share {
            share_id: "vault_share".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Vault,
            target_id: "v0".to_owned(),
            role: ROLE_MANAGER.to_string(),
            permissions: 0,
            flags: 0,
        };
        // Superseded by vault_0_admin
        let vault_0_write = Share {
            share_id: "vault_share".to_string(),
            vault_id: "v0".to_owned(),
            target_type: TargetType::Vault,
            target_id: "v0".to_owned(),
            role: ROLE_WRITE.to_string(),
            permissions: 0,
            flags: 0,
        };
        // Item in vault 1 that we don't have share for
        let item = Share {
            share_id: "item_read".to_string(),
            vault_id: "v1".to_owned(),
            target_type: TargetType::Item,
            target_id: "1".to_owned(),
            role: ROLE_READ.to_string(),
            permissions: 0,
            flags: 0,
        };
        // Only one share for this vault
        let vault_2_write = Share {
            share_id: "vault_2_share".to_string(),
            vault_id: "v2".to_owned(),
            target_type: TargetType::Vault,
            target_id: "v2".to_owned(),
            role: ROLE_WRITE.to_string(),
            permissions: 0,
            flags: 0,
        };
        // Item in vault 2 with the same access as vault.
        let item_2_write = Share {
            share_id: "item_2_write".to_string(),
            vault_id: "v2".to_owned(),
            target_type: TargetType::Item,
            target_id: "2".to_owned(),
            role: ROLE_WRITE.to_string(),
            permissions: 0,
            flags: 0,
        };
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
}
