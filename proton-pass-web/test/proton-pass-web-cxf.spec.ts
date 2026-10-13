import { describe, expect, test } from "bun:test";

import { cxf_export, cxf_import } from "./pkg/cxf/proton_pass_web";

function makeLoginItem(title: string, email: string, password: string, username: string = "") {
    return {
        title,
        note: "",
        item_uuid: "test-uuid-login",
        content: {
            Login: {
                email,
                username,
                password,
                urls: [],
                totp_uri: "",
                passkeys: [],
                autofill_urls: [],
            },
        },
        extra_fields: [],
        platform_specific: undefined,
        custom_icon: undefined,
    };
}

function makeItemWithMetadata(
    item: ReturnType<typeof makeLoginItem>,
    metadata: { created_at?: number; modified_at?: number; pinned?: boolean } = {},
) {
    return {
        item,
        metadata: {
            created_at: metadata.created_at ?? 0,
            modified_at: metadata.modified_at ?? 0,
            pinned: metadata.pinned ?? false,
        },
    };
}

function makeVaultData(name: string) {
    return {
        name,
        description: "",
        display_preferences: { icon: "Unspecified", color: "Unspecified" },
    };
}

describe("ProtonPassWeb WASM: cxf", () => {
    test("Login item round trips through export and import", () => {
        const title = "My login";
        const email = "test@example.com";
        const password = "hunter2";
        const item = makeLoginItem(title, email, password);

        const exportResult = cxf_export({
            vaults: [{ vault: makeVaultData("Personal"), items: [makeItemWithMetadata(item)] }],
            exporter_rp_id: "proton.me",
            exporter_display_name: "Proton Pass",
            timestamp: 1700000000,
        });
        expect(exportResult.warnings).toEqual([]);

        const importResult = cxf_import(exportResult.payload);
        expect(importResult.warnings).toEqual([]);
        expect(importResult.vaults.length).toEqual(1);

        const importedVault = importResult.vaults[0];
        expect(importedVault.vault.name).toEqual("Personal");
        expect(importedVault.items.length).toEqual(1);

        const importedItem = importedVault.items[0];
        if (!("Login" in importedItem.content)) {
            throw new Error("Expected Login content");
        }
        expect(importedItem.content.Login.email).toEqual(email);
        expect(importedItem.content.Login.password).toEqual(password);
    });

    test("Item metadata maps to CXF creation/modification/favorite fields", () => {
        const item = makeLoginItem("Pinned login", "pinned@example.com", "hunter2");

        const exportResult = cxf_export({
            vaults: [
                {
                    vault: makeVaultData("Personal"),
                    items: [makeItemWithMetadata(item, { created_at: 1650000000, modified_at: 1660000000, pinned: true })],
                },
            ],
            exporter_rp_id: "proton.me",
            exporter_display_name: "Proton Pass",
            timestamp: 1700000000,
        });
        expect(exportResult.warnings).toEqual([]);

        const payload = JSON.parse(exportResult.payload);
        const cxfItem = payload.accounts[0].items[0];
        expect(cxfItem.creationAt).toEqual(1650000000);
        expect(cxfItem.modifiedAt).toEqual(1660000000);
        expect(cxfItem.favorite).toEqual(true);
    });

    test("Login item with distinct email and username round trips without loss", () => {
        const title = "Login with distinct email and username";
        const email = "alice@example.com";
        const username = "alice_the_gamer";
        const password = "hunter2";
        const item = makeLoginItem(title, email, password, username);

        const exportResult = cxf_export({
            vaults: [{ vault: makeVaultData("Personal"), items: [makeItemWithMetadata(item)] }],
            exporter_rp_id: "proton.me",
            exporter_display_name: "Proton Pass",
            timestamp: 1700000000,
        });
        expect(exportResult.warnings).toEqual([]);

        const importResult = cxf_import(exportResult.payload);
        expect(importResult.warnings).toEqual([]);

        const importedItem = importResult.vaults[0].items[0];
        if (!("Login" in importedItem.content)) {
            throw new Error("Expected Login content");
        }
        expect(importedItem.content.Login.email).toEqual(email);
        expect(importedItem.content.Login.username).toEqual(username);
    });
});
