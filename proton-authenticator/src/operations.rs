use crate::AuthenticatorEntry;
use std::collections::{HashMap, HashSet};

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
}

#[derive(Clone)]
pub struct RemoteEntry {
    pub remote_id: String,
    pub entry: AuthenticatorEntry,
}

pub enum AuthenticatorOperation {
    // Update local copy of the entry
    Upsert,
    // Delete local copy
    DeleteLocal,
    // Delete local copy and make api request to delete remote
    DeleteLocalAndRemote,
    // Create remote version
    Push,
    // Conflict, user must choose what to do
    Conflict,
}

pub struct EntryOperation {
    pub remote_id: Option<String>,
    pub entry: AuthenticatorEntry,
    pub operation: AuthenticatorOperation,
}

pub fn calculate_operations_to_perform(remote: Vec<RemoteEntry>, local: Vec<LocalEntry>) -> Vec<EntryOperation> {
    let local_entries = list_to_map(local, |e| e.entry.id.to_string());
    let mut remote_entry_ids = HashSet::new();

    let mut ops = Vec::new();

    // Detect remote entries not in local
    for remote_entry in remote {
        let remote_entry_id = remote_entry.entry.id.to_string();
        match local_entries.get(&remote_entry_id) {
            Some(local_entry) => {
                // We found it locally. Check if it's pending to be deleted
                match local_entry.state {
                    AuthenticatorEntryState::Synced => {
                        // It was synced . Check if it's the same.
                        // If there are differences, perform upsert and store the remote
                        if !local_entry.entry.eq(&remote_entry.entry) {
                            ops.push(EntryOperation {
                                remote_id: Some(remote_entry.remote_id.to_string()),
                                entry: remote_entry.entry,
                                operation: AuthenticatorOperation::Upsert,
                            });
                        }
                    }
                    AuthenticatorEntryState::PendingSync => {
                        // We found it locally, but it was marked as pending to be synced.
                        // Maybe it's because of a local unsynced update
                        // Return conflict so the client preserves the most recent one
                        ops.push(EntryOperation {
                            remote_id: Some(remote_entry.remote_id.to_string()),
                            entry: remote_entry.entry,
                            operation: AuthenticatorOperation::Conflict,
                        });
                    }
                    AuthenticatorEntryState::PendingToDelete => {
                        // We found it locally, but it's marked as pending to be deleted.
                        // Store the deletion operation
                        ops.push(EntryOperation {
                            remote_id: Some(remote_entry.remote_id.to_string()),
                            entry: remote_entry.entry,
                            operation: AuthenticatorOperation::DeleteLocalAndRemote,
                        })
                    }
                }
            }
            None => {
                // We don't have it locally, store it
                ops.push(EntryOperation {
                    remote_id: Some(remote_entry.remote_id.to_string()),
                    entry: remote_entry.entry,
                    operation: AuthenticatorOperation::Upsert,
                });
            }
        }

        remote_entry_ids.insert(remote_entry_id);
    }

    // Detect local entries not in remote
    for (local_id, local_entry) in local_entries.iter() {
        // If the local entry was present in the remote it would have been processed by the other loop
        if !remote_entry_ids.contains(local_id) {
            // Local entry not in remote. Determine the reason
            match local_entry.state {
                AuthenticatorEntryState::Synced => {
                    // It was synced, and it's not there anymore. Remove it
                    ops.push(EntryOperation {
                        remote_id: None,
                        entry: local_entry.entry.clone(),
                        operation: AuthenticatorOperation::DeleteLocal,
                    })
                }
                AuthenticatorEntryState::PendingSync => {
                    // The entry had not yet been pushed to the remote
                    // Send it
                    ops.push(EntryOperation {
                        remote_id: None,
                        entry: local_entry.entry.clone(),
                        operation: AuthenticatorOperation::Push,
                    })
                }
                AuthenticatorEntryState::PendingToDelete => {
                    // Not available in the remote and we have it pending to be deleted
                    // Delete it locally
                    ops.push(EntryOperation {
                        remote_id: None,
                        entry: local_entry.entry.clone(),
                        operation: AuthenticatorOperation::DeleteLocal,
                    })
                }
            }
        }
    }

    ops
}

fn list_to_map<T, F: Fn(&T) -> String>(input: Vec<T>, f: F) -> HashMap<String, T> {
    let mut map = HashMap::new();
    for item in input {
        let key = f(&item);
        map.insert(key, item);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthenticatorEntryContent;

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

    fn local_entry_with_state(state: AuthenticatorEntryState) -> LocalEntry {
        local_entry_with_entry_and_state(random_entry(), state)
    }

    fn local_entry_with_entry_and_state(entry: AuthenticatorEntry, state: AuthenticatorEntryState) -> LocalEntry {
        LocalEntry { entry, state }
    }

    fn remote_entry_with_id(id: String) -> RemoteEntry {
        RemoteEntry {
            remote_id: id,
            entry: random_entry(),
        }
    }

    fn remote_entry() -> RemoteEntry {
        remote_entry_with_id(random_id())
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
    fn remote_in_local_pending_to_sync_with_changes_returns_conflict() {
        let remote_entry = remote_entry();
        let local_entry =
            local_entry_with_entry_and_state(modify_entry(&remote_entry.entry), AuthenticatorEntryState::PendingSync);
        let res = calculate_operations_to_perform(vec![remote_entry.clone()], vec![local_entry.clone()]);
        assert_eq!(1, res.len());

        assert!(matches!(res[0].operation, AuthenticatorOperation::Conflict));
        assert_eq!(Some(remote_entry.remote_id), res[0].remote_id);
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
}
