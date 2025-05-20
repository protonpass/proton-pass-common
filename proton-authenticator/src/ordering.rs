use crate::AuthenticatorEntry;
use std::cmp::Ordering;
use std::collections::HashMap;

#[derive(Clone)]
pub struct EntryWithOrder {
    pub entry: AuthenticatorEntry,
    pub modify_time: i64,
    pub order: i32,
}

pub fn reorder_items(local_items: &[EntryWithOrder], remote_items: &[EntryWithOrder]) -> Vec<EntryWithOrder> {
    let mut current: HashMap<String, EntryWithOrder> = HashMap::new();

    for item in local_items.iter().chain(remote_items) {
        let key = &item.entry.id;

        match current.get(key) {
            // Same id but different order → keep whichever is newer
            Some(existing) if item.order != existing.order => {
                if item.modify_time > existing.modify_time {
                    current.insert(key.to_string(), item.clone());
                }
            }

            // Not seen yet
            None => {
                current.insert(key.to_string(), item.clone());
            }

            // Same id + same order → nothing to do
            _ => {}
        }
    }

    // Sort by order
    let mut merged: Vec<EntryWithOrder> = current.into_values().collect();

    merged.sort_by(|a, b| match a.order.cmp(&b.order) {
        Ordering::Equal => a.modify_time.cmp(&b.modify_time),
        other => other,
    });

    // After the stable sort, rewrite `order` so it’s continuous
    for (idx, item) in merged.iter_mut().enumerate() {
        item.order = idx as i32;
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_URI: &str = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";

    /// Convenience constructor so the tests read well.
    fn make(id: &str, order: i32, modify: i64) -> EntryWithOrder {
        EntryWithOrder {
            entry: AuthenticatorEntry::from_uri_and_id(TEST_URI, None, id.to_string()).unwrap(),
            order,
            modify_time: modify,
        }
    }

    /// All returned items must be 0-based and strictly consecutive.
    fn assert_continuous_order(items: &[EntryWithOrder]) {
        for (expected, item) in items.iter().enumerate() {
            assert_eq!(
                item.order, expected as i32,
                "item {} should have order {expected}, has {} instead",
                item.entry.id, item.order
            );
        }
    }

    // Conflict: same id, different order – incoming is *newer*, so replace.
    #[test]
    fn picks_newer_when_order_conflicts() {
        let local = vec![make("a", 0, 100)];
        let remote = vec![make("a", 1, 200)];

        let result = reorder_items(&local, &remote);
        assert_eq!(result.len(), 1);

        let a = &result[0];
        assert_eq!(a.entry.id, "a");
        assert_eq!(a.modify_time, 200, "newer item should win");
        assert_continuous_order(&result); // renumbered to 0
    }

    // Conflict: same id, different order – incoming is *older*, keep local.
    #[test]
    fn keeps_existing_when_newer_locally() {
        let local = vec![make("b", 1, 300)];
        let remote = vec![make("b", 0, 50)];

        let result = reorder_items(&local, &remote);
        assert_eq!(result.len(), 1);

        let b = &result[0];
        assert_eq!(b.entry.id, "b");
        assert_eq!(b.modify_time, 300, "older remote must not replace newer local");
        assert_continuous_order(&result);
    }

    // Conflict-free merge: verifies sort by order
    #[test]
    fn merges_without_conflict_and_sorts_by_order() {
        let local = vec![make("c", 5, 70)];
        let remote = vec![make("d", 2, 60)];

        let result = reorder_items(&local, &remote);
        assert_eq!(result.len(), 2);

        assert_eq!(result[0].entry.id, "d"); // 2 < 5, so “d” first
        assert_eq!(result[1].entry.id, "c");
        assert_continuous_order(&result);
    }

    // Tie on `order`; verify secondary key (`modify_time`).
    #[test]
    fn break_order_ties_by_modify_time() {
        let items = vec![make("e", 0, 50), make("g", 0, 75), make("f", 0, 90)];

        let result = reorder_items(&items, &[]);
        assert_eq!(result.len(), 3);

        // ascending by modify_time (50 → 75 → 90)
        assert_eq!(result[0].entry.id, "e");
        assert_eq!(result[1].entry.id, "g");
        assert_eq!(result[2].entry.id, "f");
        assert_continuous_order(&result);
    }

    // 5. Same id and order → ignore duplicates entirely.
    #[test]
    fn ignores_duplicates_with_identical_order() {
        let local = vec![make("h", 3, 100)];
        let remote = vec![make("h", 3, 999)]; // newer but same order

        let result = reorder_items(&local, &remote);
        assert_eq!(result.len(), 1, "duplicate with same order must be dropped");
        assert_eq!(result[0].modify_time, 100, "original item must be kept");
        assert_continuous_order(&result);
    }

    // Remote-only items must remain unchanged except for order.
    #[test]
    fn handles_remote_only_items() {
        let result = reorder_items(&[], &[make("x", 5, 123)]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].entry.id, "x");
        assert_continuous_order(&result); // order reset from 5 → 0
    }
}
