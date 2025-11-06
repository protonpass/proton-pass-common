import {describe, expect, test} from "bun:test";

import {get_visible_shares} from "./pkg/worker";

describe("ProtonPassWeb WASM - Share", () => {
    test("Should return single share", () => {
        const shares = [
            {
                share_id: "share1",
                vault_id: "vault1",
                target_type: "Vault",
                target_id: "vault1",
                role: "1", // Admin
                permissions: 0,
                flags: 0,
            },
        ];

        const result = get_visible_shares(shares);
        expect(result).toHaveLength(1);
        expect(result[0]).toEqual("share1");
    });

    test("Should deduplicate shares with same target, keeping best role", () => {
        const shares = [
            {
                share_id: "share_read",
                vault_id: "vault1",
                target_type: "Item",
                target_id: "item1",
                role: "3", // Read
                permissions: 0,
                flags: 0,
            },
            {
                share_id: "share_write",
                vault_id: "vault1",
                target_type: "Item",
                target_id: "item1",
                role: "2", // Write
                permissions: 0,
                flags: 0,
            },
            {
                share_id: "share_admin",
                vault_id: "vault1",
                target_type: "Item",
                target_id: "item1",
                role: "1", // Admin
                permissions: 0,
                flags: 0,
            },
        ];

        const result = get_visible_shares(shares);
        expect(result).toHaveLength(1);
        expect(result[0]).toEqual("share_admin");
    });

    test("Should hide item shares when vault share has better or equal role", () => {
        const shares = [
            {
                share_id: "vault_write",
                vault_id: "vault1",
                target_type: "Vault",
                target_id: "vault1",
                role: "2", // Write
                permissions: 0,
                flags: 0,
            },
            {
                share_id: "item_read",
                vault_id: "vault1",
                target_type: "Item",
                target_id: "item1",
                role: "3", // Read
                permissions: 0,
                flags: 0,
            },
            {
                share_id: "item_write",
                vault_id: "vault1",
                target_type: "Item",
                target_id: "item2",
                role: "2", // Write
                permissions: 0,
                flags: 0,
            },
        ];

        const result = get_visible_shares(shares);
        expect(result).toHaveLength(1);
        expect(result[0]).toEqual("vault_write");
    });

    test("Should keep item shares when they have better role than vault", () => {
        const shares = [
            {
                share_id: "vault_read",
                vault_id: "vault1",
                target_type: "Vault",
                target_id: "vault1",
                role: "3", // Read
                permissions: 0,
                flags: 0,
            },
            {
                share_id: "item_write",
                vault_id: "vault1",
                target_type: "Item",
                target_id: "item1",
                role: "2", // Write
                permissions: 0,
                flags: 0,
            },
            {
                share_id: "item_admin",
                vault_id: "vault1",
                target_type: "Item",
                target_id: "item2",
                role: "1", // Admin
                permissions: 0,
                flags: 0,
            },
        ];

        const result = get_visible_shares(shares);
        expect(result).toHaveLength(3);
        expect(result).toContain("vault_read");
        expect(result).toContain("item_write");
        expect(result).toContain("item_admin");
    });

    test("Should keep items from different vaults", () => {
        const shares = [
            {
                share_id: "vault1_admin",
                vault_id: "vault1",
                target_type: "Vault",
                target_id: "vault1",
                role: "1", // Admin
                permissions: 0,
                flags: 0,
            },
            {
                share_id: "vault2_item_read",
                vault_id: "vault2",
                target_type: "Item",
                target_id: "item1",
                role: "3", // Read
                permissions: 0,
                flags: 0,
            },
        ];

        const result = get_visible_shares(shares);
        expect(result).toHaveLength(2);
        expect(result).toContain("vault1_admin");
        expect(result).toContain("vault2_item_read");
    });

    test("Should handle complex scenario with multiple vaults and items", () => {
        const shares = [
            // Vault 1: Admin access
            {
                share_id: "v1_admin",
                vault_id: "vault1",
                target_type: "Vault",
                target_id: "vault1",
                role: "1",
                permissions: 0,
                flags: 0,
            },
            // Vault 1: Item with read (should be hidden by vault admin)
            {
                share_id: "v1_item_read",
                vault_id: "vault1",
                target_type: "Item",
                target_id: "item1",
                role: "3",
                permissions: 0,
                flags: 0,
            },
            // Vault 2: Read access
            {
                share_id: "v2_read",
                vault_id: "vault2",
                target_type: "Vault",
                target_id: "vault2",
                role: "3",
                permissions: 0,
                flags: 0,
            },
            // Vault 2: Item with write (should be kept as it's better than vault read)
            {
                share_id: "v2_item_write",
                vault_id: "vault2",
                target_type: "Item",
                target_id: "item2",
                role: "2",
                permissions: 0,
                flags: 0,
            },
            // Vault 3: No vault share, only item
            {
                share_id: "v3_item_admin",
                vault_id: "vault3",
                target_type: "Item",
                target_id: "item3",
                role: "1",
                permissions: 0,
                flags: 0,
            },
        ];

        const result = get_visible_shares(shares);
        expect(result).toHaveLength(4);
        expect(result).toContain("v1_admin");
        expect(result).toContain("v2_read");
        expect(result).toContain("v2_item_write");
        expect(result).toContain("v3_item_admin");
        expect(result).not.toContain("v1_item_read");
    });
});

