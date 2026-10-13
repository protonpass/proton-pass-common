import { describe, expect, test } from "bun:test";

import {
    folder_data_deserialize,
    folder_data_perform_update,
    folder_data_serialize,
    item_data_deserialize,
    item_data_perform_update,
    item_data_serialize,
    vault_data_deserialize,
    vault_data_perform_update,
    vault_data_serialize,
} from "./pkg/proto/proton_pass_web";

function makeNoteItem(title: string, note: string, customIcon?: Uint8Array) {
    return {
        title,
        note,
        item_uuid: "test-uuid",
        content: { Note: undefined },
        extra_fields: [],
        platform_specific: undefined,
        custom_icon: customIcon,
    };
}

function makeLoginItem(title: string, urls, customIcon?: Uint8Array) {
    return {
        title,
        note: "",
        item_uuid: "test-uuid-login",
        content: {
            Login: {
                email: "test@example.com",
                username: "testuser",
                password: "password123",
                urls,
                totp_uri: "",
                passkeys: [],
                autofill_urls: [],
            },
        },
        extra_fields: [],
        platform_specific: undefined,
        custom_icon: customIcon,
    };
}

function makeVaultData(name: string, description: string, icon, color) {
    return {
        name,
        description,
        display_preferences: { icon, color },
    };
}

describe("ProtonPassWeb WASM: types", () => {
    test("Item round trip serialize/deserialize preserves all fields", () => {
        const item = makeNoteItem("My note", "Some content");
        const bytes = item_data_serialize(item);
        const result = item_data_deserialize(bytes);

        expect(result.title).toEqual("My note");
        expect(result.note).toEqual("Some content");
        expect(result.item_uuid).toEqual("test-uuid");
        expect(result.content).toEqual({ Note: undefined });
    });

    test("Item round trip serialize/deserialize preserves custom_icon", () => {
        const customIconBytes = [1, 2, 3, 4];
        const item = makeNoteItem("My note", "Some content", new Uint8Array(customIconBytes));
        const bytes = item_data_serialize(item);
        const result = item_data_deserialize(bytes);

        expect(Array.from(result.custom_icon)).toEqual(customIconBytes);
    });

    test("Item without custom_icon round trips as undefined", () => {
        const item = makeNoteItem("My note", "Some content");
        const bytes = item_data_serialize(item);
        const result = item_data_deserialize(bytes);

        expect(result.custom_icon).toBeUndefined();
    });

    test("Item perform_update clears custom_icon when update omits it", () => {
        const originalCustomIconBytes = [1, 2, 3, 4];
        const original = makeNoteItem("My note", "Some content", new Uint8Array(originalCustomIconBytes));
        const originalBytes = item_data_serialize(original);

        const updated = makeNoteItem("Updated title", "Some content");
        const updatedBytes = item_data_perform_update(originalBytes, updated);
        const result = item_data_deserialize(updatedBytes);

        expect(result.title).toEqual("Updated title");
        expect(result.custom_icon).toBeUndefined();
    });

    test("Item perform_update replaces custom_icon when update sets it", () => {
        const originalCustomIconBytes = [1, 2, 3, 4];
        const updatedCustomIconBytes = [5, 6, 7, 8];
        const original = makeNoteItem("My note", "Some content", new Uint8Array(originalCustomIconBytes));
        const originalBytes = item_data_serialize(original);

        const updated = makeNoteItem("My note", "Some content", new Uint8Array(updatedCustomIconBytes));
        const updatedBytes = item_data_perform_update(originalBytes, updated);
        const result = item_data_deserialize(updatedBytes);

        expect(Array.from(result.custom_icon)).toEqual(updatedCustomIconBytes);
    });

    test("Item perform_update on a basic field preserves other fields", () => {
        const original = makeNoteItem("Original title", "Original note");
        const originalBytes = item_data_serialize(original);

        const updated = makeNoteItem("Updated title", "Original note");
        const updatedBytes = item_data_perform_update(originalBytes, updated);
        const result = item_data_deserialize(updatedBytes);

        expect(result.title).toEqual("Updated title");
        expect(result.note).toEqual("Original note");
    });

    test("Item perform_update on a repeated field replaces rather than appends", () => {
        const original = makeLoginItem("Login item", ["https://example.com", "https://app.example.com"]);
        const originalBytes = item_data_serialize(original);

        const updated = makeLoginItem("Login item", ["https://new.example.com"]);
        const updatedBytes = item_data_perform_update(originalBytes, updated);
        const result = item_data_deserialize(updatedBytes);

        if (!("Login" in result.content)) {
            throw new Error("Expected Login content");
        }
        expect(result.content.Login.urls).toEqual(["https://new.example.com"]);
    });

    test("Login urls migrate to autofill urls on serialize", () => {
        const urls = ["https://example.com", "https://app.example.com"];
        const item = makeLoginItem("Login item", urls);

        const bytes = item_data_serialize(item);
        const result = item_data_deserialize(bytes);

        if (!("Login" in result.content)) {
            throw new Error("Expected Login content");
        }
        expect(result.content.Login.autofill_urls.map((autofillUrl) => autofillUrl.url)).toEqual(urls);
    });

    test("Vault round trip", () => {
        const vault = makeVaultData("My vault", "A description", "Icon5", "Color3");
        const bytes = vault_data_serialize(vault);
        const result = vault_data_deserialize(bytes);

        expect(result).toEqual(vault);
    });

    test("Vault perform_update on display.icon", () => {
        const original = makeVaultData("My vault", "A description", "Custom", "Color1");
        const originalBytes = vault_data_serialize(original);

        const updated = makeVaultData("My vault", "A description", "Icon5", "Color1");
        const updatedBytes = vault_data_perform_update(originalBytes, updated);
        const result = vault_data_deserialize(updatedBytes);

        expect(result.display_preferences.icon).toEqual("Icon5");
    });

    test("Folder round trip", () => {
        const folder = { name: "My folder" };
        const bytes = folder_data_serialize(folder);
        const result = folder_data_deserialize(bytes);

        expect(result).toEqual(folder);
    });

    test("Folder perform_update on name", () => {
        const original = { name: "Original" };
        const originalBytes = folder_data_serialize(original);

        const updated = { name: "Updated" };
        const updatedBytes = folder_data_perform_update(originalBytes, updated);
        const result = folder_data_deserialize(updatedBytes);

        expect(result.name).toEqual("Updated");
    });
});
