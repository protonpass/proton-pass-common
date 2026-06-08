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

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum ItemFlag {
    SkipHealthCheck = 1 << 0, // 1
    EmailBreached = 1 << 1,   // 2
    AliasDisabled = 1 << 2,   // 4
    ItemHasFiles = 1 << 3,    // 8
    ItemHasHadFiles = 1 << 4, // 16
}

impl ItemFlag {
    /// Parse a u64 bitmask value into a `Vec<ItemFlag>`
    pub fn parse_flags(flags: u64) -> Vec<ItemFlag> {
        let mut result = Vec::new();

        if flags & (ItemFlag::SkipHealthCheck as u64) != 0 {
            result.push(ItemFlag::SkipHealthCheck);
        }
        if flags & (ItemFlag::EmailBreached as u64) != 0 {
            result.push(ItemFlag::EmailBreached);
        }
        if flags & (ItemFlag::AliasDisabled as u64) != 0 {
            result.push(ItemFlag::AliasDisabled);
        }
        if flags & (ItemFlag::ItemHasFiles as u64) != 0 {
            result.push(ItemFlag::ItemHasFiles);
        }
        if flags & (ItemFlag::ItemHasHadFiles as u64) != 0 {
            result.push(ItemFlag::ItemHasHadFiles);
        }

        result
    }

    /// Convert a `Vec<ItemFlag>` back to a u64 bitmask
    pub fn to_bitmask(flags: &[ItemFlag]) -> u64 {
        flags.iter().fold(0u64, |acc, flag| acc | (*flag as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_flags() {
        // Test individual flags
        assert_eq!(ItemFlag::parse_flags(1), vec![ItemFlag::SkipHealthCheck]);
        assert_eq!(ItemFlag::parse_flags(2), vec![ItemFlag::EmailBreached]);
        assert_eq!(ItemFlag::parse_flags(4), vec![ItemFlag::AliasDisabled]);
        assert_eq!(ItemFlag::parse_flags(8), vec![ItemFlag::ItemHasFiles]);
        assert_eq!(ItemFlag::parse_flags(16), vec![ItemFlag::ItemHasHadFiles]);

        // Test combined flags
        let combined = ItemFlag::parse_flags(3); // 1 + 2
        assert!(combined.contains(&ItemFlag::SkipHealthCheck));
        assert!(combined.contains(&ItemFlag::EmailBreached));
        assert_eq!(combined.len(), 2);

        // Test all flags
        let all_flags = ItemFlag::parse_flags(31); // 1 + 2 + 4 + 8 + 16
        assert_eq!(all_flags.len(), 5);

        // Test no flags
        assert_eq!(ItemFlag::parse_flags(0), vec![]);
    }

    #[test]
    fn test_to_bitmask() {
        assert_eq!(ItemFlag::to_bitmask(&[ItemFlag::SkipHealthCheck]), 1);
        assert_eq!(ItemFlag::to_bitmask(&[ItemFlag::EmailBreached]), 2);
        assert_eq!(
            ItemFlag::to_bitmask(&[ItemFlag::SkipHealthCheck, ItemFlag::EmailBreached]),
            3
        );
        assert_eq!(ItemFlag::to_bitmask(&[]), 0);
    }
}
