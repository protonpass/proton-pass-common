import { describe, expect, test } from "bun:test";

import { find_duplicate_items_wasm } from "./pkg/duplicate/proton_pass_web";

function loginItem(
    itemId: string,
    opts: { username?: string; email?: string; password: string; urls?: string[] }
) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: "title",
            note: "",
            item_uuid: `${itemId}-uuid`,
            content: {
                Login: {
                    email: opts.email ?? "",
                    username: opts.username ?? "",
                    password: opts.password,
                    urls: opts.urls ?? [],
                    totp_uri: "",
                    passkeys: [],
                    autofill_urls: [],
                },
            },
            extra_fields: [],
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function noteItem(itemId: string, note: string) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: "title",
            note,
            item_uuid: `${itemId}-uuid`,
            content: { Note: null },
            extra_fields: [],
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function aliasItem(itemId: string) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: "title",
            note: "",
            item_uuid: `${itemId}-uuid`,
            content: { Alias: null },
            extra_fields: [],
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function wifiItem(itemId: string, ssid: string) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: "title",
            note: "",
            item_uuid: `${itemId}-uuid`,
            content: { Wifi: { ssid, password: "pw", security: "WPA2", sections: [] } },
            extra_fields: [],
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function sshItem(itemId: string) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: "title",
            note: "",
            item_uuid: `${itemId}-uuid`,
            content: { SshKey: { private_key: "priv", public_key: "pub", sections: [] } },
            extra_fields: [],
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function groupIds(groups: { items: { item_id: string }[] }[]) {
    return groups.map((g) => g.items.map((i) => i.item_id).sort()).sort();
}

describe("ProtonPassWeb WASM - Duplicate item detection", () => {
    test("logins with same username, password and related urls are duplicates", () => {
        const items = [
            loginItem("1", { username: "bob", password: "pw", urls: ["https://amazon.com/login"] }),
            loginItem("2", { username: "bob", password: "pw", urls: ["https://www.amazon.com/account"] }),
        ];

        const groups = find_duplicate_items_wasm(items);
        expect(groupIds(groups)).toEqual([["1", "2"]]);
    });

    test("logins with same identity and password but unrelated urls are not duplicates", () => {
        const items = [
            loginItem("1", { username: "bob", password: "pw", urls: ["https://amazon.com/login"] }),
            loginItem("2", { username: "bob", password: "pw", urls: ["https://uber.com/login"] }),
        ];

        expect(find_duplicate_items_wasm(items)).toHaveLength(0);
    });

    test("logins matching by email instead of username are duplicates", () => {
        const items = [
            loginItem("1", { email: "bob@proton.me", password: "pw" }),
            loginItem("2", { email: "bob@proton.me", password: "pw" }),
        ];

        const groups = find_duplicate_items_wasm(items);
        expect(groupIds(groups)).toEqual([["1", "2"]]);
    });

    test("logins with different identity are not duplicates", () => {
        const items = [
            loginItem("1", { username: "bob", password: "pw" }),
            loginItem("2", { username: "alice", password: "pw" }),
        ];

        expect(find_duplicate_items_wasm(items)).toHaveLength(0);
    });

    test("logins are transitively grouped", () => {
        const items = [
            loginItem("1", { username: "bob", password: "pw", urls: ["https://amazon.com"] }),
            loginItem("2", { username: "bob", password: "pw", urls: ["https://amazon.com", "https://uber.com"] }),
            loginItem("3", { username: "bob", password: "pw", urls: ["https://uber.com"] }),
        ];

        const groups = find_duplicate_items_wasm(items);
        expect(groupIds(groups)).toEqual([["1", "2", "3"]]);
    });

    test("notes with same note are duplicates", () => {
        const items = [noteItem("1", "same note"), noteItem("2", "same note")];

        const groups = find_duplicate_items_wasm(items);
        expect(groupIds(groups)).toEqual([["1", "2"]]);
    });

    test("notes with different note are not duplicates", () => {
        const items = [noteItem("1", "note a"), noteItem("2", "note b")];

        expect(find_duplicate_items_wasm(items)).toHaveLength(0);
    });

    test("aliases are never duplicates", () => {
        const items = [aliasItem("1"), aliasItem("2")];

        expect(find_duplicate_items_wasm(items)).toHaveLength(0);
    });

    test("different item types are never duplicates", () => {
        const items = [loginItem("1", { username: "bob", email: "bob@proton.me", password: "pw" }), noteItem("2", "")];

        expect(find_duplicate_items_wasm(items)).toHaveLength(0);
    });

    test("wifi and ssh are dedicated types and never match each other", () => {
        const items = [wifiItem("1", "network"), sshItem("2")];

        expect(find_duplicate_items_wasm(items)).toHaveLength(0);
    });

    test("items with no duplicates are excluded from results", () => {
        const items = [
            loginItem("1", { username: "bob", password: "pw" }),
            loginItem("2", { username: "alice", password: "pw2" }),
        ];

        expect(find_duplicate_items_wasm(items)).toHaveLength(0);
    });
});
