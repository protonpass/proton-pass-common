use crate::utils::list_to_map;
use crate::AuthenticatorEntry;
use std::collections::HashSet;

#[derive(Clone, Copy)]
pub enum AuthenticatorEntryState {
    Synced,
    PendingSync,
    PendingToDelete,
}

#[derive(Clone)]
pub struct LocalEntry {
    pub entry: AuthenticatorEntry,
    pub state: AuthenticatorEntryState,
    /// `modify_time` the server knew about when the entry was fetched
    pub modify_time: i64,
    /// local changes that could not yet be pushed; `None` == no offline edits
    pub local_modify_time: Option<i64>,
}

#[derive(Clone)]
pub struct RemoteEntry {
    pub remote_id: String,
    pub entry: AuthenticatorEntry,
    /// last-modified (time‐millis since Unix epoch) as returned by the server
    pub modify_time: i64,
}

#[derive(Debug)]
pub enum AuthenticatorOperation {
    // Update local copy of the entry
    Upsert,
    // Delete local copy
    DeleteLocal,
    // Delete local copy and make api request to delete remote
    DeleteLocalAndRemote,
    // Create remote version
    Push,
}

#[derive(Debug)]
pub struct EntryOperation {
    pub remote_id: Option<String>,
    pub entry: AuthenticatorEntry,
    pub operation: AuthenticatorOperation,
}

pub fn calculate_operations_to_perform(remote: Vec<RemoteEntry>, local: Vec<LocalEntry>) -> Vec<EntryOperation> {
    let local_entries = list_to_map(local, |e| e.entry.id.to_string());
    let mut remote_entry_ids = HashSet::new();
    let mut ops = Vec::new();

    // Remote present
    for remote_entry in remote {
        let remote_entry_id = remote_entry.entry.id.to_string();

        match local_entries.get(&remote_entry_id) {
            // Also exists locally
            Some(local_entry) => match local_entry.state {
                // Synced – check if there are changes
                AuthenticatorEntryState::Synced => {
                    if !local_entry.entry.eq(&remote_entry.entry) {
                        ops.push(EntryOperation {
                            remote_id: Some(remote_entry.remote_id.clone()),
                            entry: remote_entry.entry.clone(),
                            operation: AuthenticatorOperation::Upsert,
                        });
                    }
                }

                // Pending offline update
                AuthenticatorEntryState::PendingSync => {
                    let same_timestamp = remote_entry.modify_time == local_entry.modify_time;

                    match (same_timestamp, local_entry.local_modify_time) {
                        // Equal mtime + offline edits -> push local version
                        (true, Some(_)) => ops.push(EntryOperation {
                            remote_id: Some(remote_entry.remote_id.clone()),
                            entry: local_entry.entry.clone(),
                            operation: AuthenticatorOperation::Push,
                        }),

                        // Equal mtime + no offline edits -> check if content is the same
                        (true, None) => {
                            if local_entry.entry.eq(&remote_entry.entry) {
                                // Same content -> upsert to link local entry to remote_id
                                ops.push(EntryOperation {
                                    remote_id: Some(remote_entry.remote_id.clone()),
                                    entry: remote_entry.entry.clone(),
                                    operation: AuthenticatorOperation::Upsert,
                                });
                            } else {
                                // Different content -> push local version
                                ops.push(EntryOperation {
                                    remote_id: Some(remote_entry.remote_id.clone()),
                                    entry: local_entry.entry.clone(),
                                    operation: AuthenticatorOperation::Push,
                                });
                            }
                        }

                        // Different mtime + no offline edits -> remote wins
                        (false, None) => ops.push(EntryOperation {
                            remote_id: Some(remote_entry.remote_id.clone()),
                            entry: remote_entry.entry.clone(),
                            operation: AuthenticatorOperation::Upsert,
                        }),

                        // Different mtime + offline edits -> compare times, most recent wins
                        _ => {
                            let local_time = local_entry.local_modify_time.unwrap_or(local_entry.modify_time);
                            if remote_entry.modify_time > local_time {
                                // Remote is newer, use remote version
                                ops.push(EntryOperation {
                                    remote_id: Some(remote_entry.remote_id.clone()),
                                    entry: remote_entry.entry.clone(),
                                    operation: AuthenticatorOperation::Upsert,
                                });
                            } else {
                                // Local is newer or equal, push local version
                                ops.push(EntryOperation {
                                    remote_id: Some(remote_entry.remote_id.clone()),
                                    entry: local_entry.entry.clone(),
                                    operation: AuthenticatorOperation::Push,
                                });
                            }
                        }
                    }
                }

                // Pending deletion
                AuthenticatorEntryState::PendingToDelete => ops.push(EntryOperation {
                    remote_id: Some(remote_entry.remote_id.clone()),
                    entry: remote_entry.entry.clone(),
                    operation: AuthenticatorOperation::DeleteLocalAndRemote,
                }),
            },

            // Only on the server ─> store it locally
            None => ops.push(EntryOperation {
                remote_id: Some(remote_entry.remote_id.clone()),
                entry: remote_entry.entry.clone(),
                operation: AuthenticatorOperation::Upsert,
            }),
        };

        remote_entry_ids.insert(remote_entry_id);
    }

    // Only available locally
    for (local_id, local_entry) in local_entries.iter() {
        if !remote_entry_ids.contains(local_id) {
            match local_entry.state {
                AuthenticatorEntryState::Synced => ops.push(EntryOperation {
                    remote_id: None,
                    entry: local_entry.entry.clone(),
                    operation: AuthenticatorOperation::DeleteLocal,
                }),
                AuthenticatorEntryState::PendingSync => ops.push(EntryOperation {
                    remote_id: None,
                    entry: local_entry.entry.clone(),
                    operation: AuthenticatorOperation::Push,
                }),
                AuthenticatorEntryState::PendingToDelete => ops.push(EntryOperation {
                    remote_id: None,
                    entry: local_entry.entry.clone(),
                    operation: AuthenticatorOperation::DeleteLocal,
                }),
            }
        }
    }

    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthenticatorEntryContent;

    const NOW: i64 = 1_700_000_000; // 2023-11-14T06:13:20Z
    const LATE: i64 = NOW + 1_000; // a bit later
    const VERY_LATE: i64 = NOW + 2_000; // even later

    fn local_entry_with_entry_state_and_times(
        entry: AuthenticatorEntry,
        state: AuthenticatorEntryState,
        modify_time: i64,
        local_modify_time: Option<i64>,
    ) -> LocalEntry {
        LocalEntry {
            entry,
            state,
            modify_time,
            local_modify_time,
        }
    }

    fn local_entry_with_state(state: AuthenticatorEntryState) -> LocalEntry {
        local_entry_with_entry_state_and_times(random_entry(), state, NOW, None)
    }

    fn local_entry_with_entry_and_state(entry: AuthenticatorEntry, state: AuthenticatorEntryState) -> LocalEntry {
        local_entry_with_entry_state_and_times(entry, state, NOW, None)
    }

    fn remote_entry_with_id_and_time(id: String, modify_time: i64) -> RemoteEntry {
        RemoteEntry {
            remote_id: id,
            entry: random_entry(),
            modify_time,
        }
    }

    fn remote_entry() -> RemoteEntry {
        remote_entry_with_id_and_time(random_id(), NOW)
    }

    fn modify_entry(entry: &AuthenticatorEntry) -> AuthenticatorEntry {
        let mut cloned = entry.clone();
        cloned.content = match cloned.content {
            AuthenticatorEntryContent::Totp(mut totp) => {
                totp.issuer = Some(random_id());
                AuthenticatorEntryContent::Totp(totp)
            }
            AuthenticatorEntryContent::Steam(mut steam) => {
                steam.name = Some(random_id());
                AuthenticatorEntryContent::Steam(steam)
            }
        };

        cloned
    }

    fn random_id() -> String {
        use rand::RngCore;

        let mut res = String::new();
        let dict = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for _ in 0..10 {
            let idx = rand::thread_rng().next_u32() as usize % dict.chars().count();
            res.push(dict.chars().nth(idx).unwrap());
        }

        res
    }

    fn random_entry() -> AuthenticatorEntry {
        AuthenticatorEntry::from_uri(
            "otpauth://totp/myissuer%3Amylabel?period=15&digits=8&algorithm=SHA256&secret=MYSECRET&issuer=myissuer",
            None,
        )
        .unwrap()
    }

    #[test]
    fn can_handle_empty_lists() {
        let res = calculate_operations_to_perform(vec![], vec![]);
        assert!(res.is_empty());
    }

    #[test]
    fn remote_not_in_local_returns_insert_operation() {
        let remote_entry = remote_entry();
        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![]);
        assert_eq!(1, res.len());

        assert!(matches!(res[0].operation, AuthenticatorOperation::Upsert));
        assert_eq!(remote_entry.entry.id, res[0].entry.id);
        assert_eq!(Some(remote_entry.remote_id), res[0].remote_id);
    }

    #[test]
    fn local_synced_not_in_remote_returns_delete_local_operation() {
        let local_entry = local_entry_with_state(AuthenticatorEntryState::Synced);
        let res = calculate_operations_to_perform(vec![], vec![local_entry.clone()]);
        assert_eq!(1, res.len());

        assert!(matches!(res[0].operation, AuthenticatorOperation::DeleteLocal));
        assert_eq!(local_entry.entry.id, res[0].entry.id);
    }

    #[test]
    fn local_pending_not_in_remote_returns_push_operation() {
        let local_entry = local_entry_with_state(AuthenticatorEntryState::PendingSync);
        let res = calculate_operations_to_perform(vec![], vec![local_entry.clone()]);
        assert_eq!(1, res.len());

        assert!(matches!(res[0].operation, AuthenticatorOperation::Push));
        assert_eq!(local_entry.entry.id, res[0].entry.id);
    }

    #[test]
    fn local_pending_to_delete_not_in_remote_returns_delete_local() {
        let local_entry = local_entry_with_state(AuthenticatorEntryState::PendingToDelete);
        let res = calculate_operations_to_perform(vec![], vec![local_entry.clone()]);
        assert_eq!(1, res.len());

        assert!(matches!(res[0].operation, AuthenticatorOperation::DeleteLocal));
        assert_eq!(local_entry.entry.id, res[0].entry.id);
    }

    #[test]
    fn remote_in_local_with_no_changes_returns_nothing() {
        let remote_entry = remote_entry();
        let local_entry = local_entry_with_entry_and_state(remote_entry.entry.clone(), AuthenticatorEntryState::Synced);
        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry.clone()]);
        assert!(res.is_empty());
    }

    #[test]
    fn remote_in_local_synced_with_remote_changes_returns_upsert() {
        let remote_entry = remote_entry();
        let local_entry =
            local_entry_with_entry_and_state(modify_entry(&remote_entry.entry), AuthenticatorEntryState::Synced);
        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry.clone()]);
        assert_eq!(1, res.len());

        assert!(matches!(res[0].operation, AuthenticatorOperation::Upsert));

        // Remote content is returned
        assert_eq!(remote_entry.entry.content, res[0].entry.content);
        assert_eq!(Some(remote_entry.remote_id), res[0].remote_id);
    }

    #[test]
    fn remote_in_local_pending_to_sync_with_changes_returns_upsert_when_remote_newer() {
        let remote_entry = remote_entry_with_id_and_time(random_id(), LATE); // Remote is newer
        let local_entry = LocalEntry {
            entry: modify_entry(&remote_entry.entry),
            state: AuthenticatorEntryState::PendingSync,
            modify_time: NOW,
            local_modify_time: Some(NOW), // Local edit at same time as original modify_time
        };
        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry.clone()]);
        assert_eq!(1, res.len());

        assert!(matches!(res[0].operation, AuthenticatorOperation::Upsert));
        assert_eq!(Some(remote_entry.remote_id), res[0].remote_id);
        assert_eq!(remote_entry.entry.content, res[0].entry.content); // Remote content wins
    }

    #[test]
    fn remote_in_local_pending_to_delete_returns_delete_remote_local() {
        let remote_entry = remote_entry();
        let local_entry =
            local_entry_with_entry_and_state(remote_entry.entry.clone(), AuthenticatorEntryState::PendingToDelete);
        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry.clone()]);
        assert_eq!(1, res.len());

        assert!(matches!(res[0].operation, AuthenticatorOperation::DeleteLocalAndRemote));
        assert_eq!(Some(remote_entry.remote_id), res[0].remote_id);
    }

    #[test]
    fn pending_sync_same_mtime_but_offline_edit_pushes() {
        let remote_entry = remote_entry(); // mtime == NOW
        let local_auth_entry = modify_entry(&remote_entry.entry); // local changes

        let local_entry = LocalEntry {
            entry: local_auth_entry.clone(),
            state: AuthenticatorEntryState::PendingSync,
            modify_time: NOW,
            local_modify_time: Some(VERY_LATE), // unsynced edit
        };

        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry]);
        assert_eq!(1, res.len());
        assert!(matches!(res[0].operation, AuthenticatorOperation::Push));
        // local version is the one pushed
        assert_eq!(local_auth_entry.content, res[0].entry.content);
    }

    #[test]
    fn pending_sync_remote_newer_no_local_edit_upserts() {
        let remote_entry = remote_entry_with_id_and_time(random_id(), LATE); // LATE > NOW

        let local_entry = LocalEntry {
            entry: remote_entry.entry.clone(), // same content, just older timestamp
            state: AuthenticatorEntryState::PendingSync,
            modify_time: NOW,
            local_modify_time: None,
        };

        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry]);
        assert_eq!(1, res.len());
        assert!(matches!(res[0].operation, AuthenticatorOperation::Upsert));
        // remote wins
        assert_eq!(remote_entry.modify_time, LATE);
    }

    #[test]
    fn pending_sync_both_modified_local_newer_wins() {
        let remote_entry = remote_entry_with_id_and_time(random_id(), LATE); // remote changed
        let local_entry = LocalEntry {
            entry: modify_entry(&remote_entry.entry), // also edited offline
            state: AuthenticatorEntryState::PendingSync,
            modify_time: NOW,
            local_modify_time: Some(VERY_LATE), // Local is newer than remote
        };

        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry.clone()]);
        assert_eq!(1, res.len());
        assert!(matches!(res[0].operation, AuthenticatorOperation::Push));
        assert_eq!(local_entry.entry.content, res[0].entry.content); // Local content wins
    }

    #[test]
    fn pending_sync_both_modified_remote_newer_wins() {
        let remote_entry = remote_entry_with_id_and_time(random_id(), VERY_LATE); // remote is newer
        let local_entry = LocalEntry {
            entry: modify_entry(&remote_entry.entry), // also edited offline
            state: AuthenticatorEntryState::PendingSync,
            modify_time: NOW,
            local_modify_time: Some(LATE), // Local is older than remote
        };

        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry.clone()]);
        assert_eq!(1, res.len());
        assert!(matches!(res[0].operation, AuthenticatorOperation::Upsert));
        assert_eq!(remote_entry.entry.content, res[0].entry.content); // Remote content wins
    }

    #[test]
    fn local_equals_remote() {
        let id = random_id();
        let remote = remote_entry_with_id_and_time(id.clone(), NOW);
        let local_entry = LocalEntry {
            entry: remote.entry.clone(),
            state: AuthenticatorEntryState::PendingSync,
            modify_time: NOW,
            local_modify_time: None,
        };

        let res = calculate_operations_to_perform(vec![remote.clone()], vec![local_entry.clone()]);
        assert_eq!(1, res.len());
        assert!(matches!(res[0].operation, AuthenticatorOperation::Upsert));
        assert_eq!(local_entry.entry.content, res[0].entry.content);
        assert_eq!(remote.entry.content, res[0].entry.content);
        assert_eq!(Some(id), res[0].remote_id)
    }

    #[test]
    fn local_differs_from_remote() {
        let id = random_id();
        let remote = remote_entry_with_id_and_time(id.clone(), NOW);
        let local_entry = LocalEntry {
            entry: modify_entry(&remote.entry), // Different content
            state: AuthenticatorEntryState::PendingSync,
            modify_time: NOW,
            local_modify_time: None,
        };

        let res = calculate_operations_to_perform(vec![remote], vec![local_entry.clone()]);
        assert_eq!(1, res.len());
        assert!(matches!(res[0].operation, AuthenticatorOperation::Push));
        assert_eq!(local_entry.entry.content, res[0].entry.content); // Local content is pushed
        assert_eq!(Some(id), res[0].remote_id)
    }
}
