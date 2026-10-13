import { describe, expect, test } from "bun:test";

import { plan_group_merge_wasm, plan_item_merge_wasm } from "./pkg/duplicate/proton_pass_web";

function passkey(keyId: string) {
    return {
        key_id: keyId,
        content: [],
        domain: "example.com",
        rp_id: "example.com",
        rp_name: "",
        user_name: "",
        user_display_name: "",
        user_id: [],
        create_time: 0,
        note: "",
        credential_id: [],
        user_handle: [],
        creation_data: undefined,
    };
}

function loginItem(
    itemId: string,
    opts: {
        title?: string;
        username?: string;
        password?: string;
        totpUri?: string;
        urls?: string[];
        passkeys?: ReturnType<typeof passkey>[];
        extraFields?: { name: string; type: string; value: string }[];
    } = {}
) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: opts.title ?? "title",
            note: "",
            item_uuid: `${itemId}-uuid`,
            content: {
                Login: {
                    email: "",
                    username: opts.username ?? "",
                    password: opts.password ?? "",
                    urls: opts.urls ?? [],
                    totp_uri: opts.totpUri ?? "",
                    passkeys: opts.passkeys ?? [],
                    autofill_urls: [],
                },
            },
            extra_fields: (opts.extraFields ?? []).map((field) => ({
                name: field.name,
                content: { [field.type]: field.value },
            })),
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function noteItem(itemId: string, opts: { title?: string; note?: string; extraFields?: { name: string; type: string; value: string }[] } = {}) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: opts.title ?? "title",
            note: opts.note ?? "",
            item_uuid: `${itemId}-uuid`,
            content: { Note: null },
            extra_fields: (opts.extraFields ?? []).map((field) => ({
                name: field.name,
                content: { [field.type]: field.value },
            })),
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function loginOf(item: { content: { Login: any } }) {
    return item.content.Login;
}

function creditCardItem(
    itemId: string,
    opts: { title?: string; cardholderName?: string; number?: string; pin?: string } = {}
) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: opts.title ?? "title",
            note: "",
            item_uuid: `${itemId}-uuid`,
            content: {
                CreditCard: {
                    cardholder_name: opts.cardholderName ?? "Bob",
                    card_type: "Visa",
                    number: opts.number ?? "",
                    verification_number: "123",
                    expiration_date: "12/28",
                    pin: opts.pin ?? "",
                },
            },
            extra_fields: [],
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function wifiItem(itemId: string, opts: { title?: string; ssid?: string; password?: string; security?: string } = {}) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: opts.title ?? "title",
            note: "",
            item_uuid: `${itemId}-uuid`,
            content: {
                Wifi: {
                    ssid: opts.ssid ?? "",
                    password: opts.password ?? "",
                    security: opts.security ?? "UnspecifiedWifiSecurity",
                    sections: [],
                },
            },
            extra_fields: [],
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function customItem(itemId: string, opts: { title?: string; sectionName?: string; fields?: { name: string; type: string; value: string }[] } = {}) {
    return {
        item_id: itemId,
        share_id: "share",
        item: {
            title: opts.title ?? "title",
            note: "",
            item_uuid: `${itemId}-uuid`,
            content: {
                Custom: {
                    sections: [
                        {
                            section_name: opts.sectionName ?? "section",
                            section_fields: (opts.fields ?? []).map((field) => ({
                                name: field.name,
                                content: { [field.type]: field.value },
                            })),
                        },
                    ],
                },
            },
            extra_fields: [],
            platform_specific: undefined,
            custom_icon: undefined,
        },
    };
}

function extraFieldsOf(item: { extra_fields: { name: string; content: Record<string, string> }[] }) {
    return item.extra_fields.map((field) => ({ name: field.name, content: field.content }));
}

describe("ProtonPassWeb WASM - Item merge", () => {
    test("titles differ keeps primary title", () => {
        const primary = loginItem("1", { title: "Amazon", username: "bob", password: "pw" });
        const secondary = loginItem("2", { title: "Amazon (old)", username: "bob", password: "pw" });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(plan.merged_item.title).toBe("Amazon");
        expect(plan.actions.find((a) => a.field === "Title").kind).toBe("KeepPrimary");
    });

    test("different totp secret is preserved as totp custom field", () => {
        const primary = loginItem("1", { title: "Amazon", username: "bob", password: "pw", totpUri: "otpauth://totp/primary" });
        const secondary = loginItem("2", { title: "Amazon", username: "bob", password: "pw", totpUri: "otpauth://totp/secondary" });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(loginOf(plan.merged_item).totp_uri).toBe("otpauth://totp/primary");
        expect(plan.merged_item.extra_fields).toEqual([
            { name: "Amazon - TOTP", content: { Totp: "otpauth://totp/secondary" } },
        ]);
        expect(plan.actions.find((a) => a.field === "Totp").kind).toBe("ConflictToCustomField");
    });

    test("empty primary totp is filled from secondary", () => {
        const primary = loginItem("1", { title: "Amazon", username: "bob", password: "pw" });
        const secondary = loginItem("2", { title: "Amazon", username: "bob", password: "pw", totpUri: "otpauth://totp/secondary" });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(loginOf(plan.merged_item).totp_uri).toBe("otpauth://totp/secondary");
        expect(plan.merged_item.extra_fields).toHaveLength(0);
        expect(plan.actions.find((a) => a.field === "Totp").kind).toBe("TakeSecondary");
    });

    test("urls are unioned primary first with exact duplicates removed", () => {
        const primary = loginItem("1", { title: "Amazon", username: "bob", password: "pw", urls: ["https://amazon.com", "https://shop.com"] });
        const secondary = loginItem("2", { title: "Amazon", username: "bob", password: "pw", urls: ["https://amazon.com", "https://smile.amazon.com"] });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(loginOf(plan.merged_item).urls).toEqual(["https://amazon.com", "https://shop.com", "https://smile.amazon.com"]);
        expect(loginOf(plan.merged_item).autofill_urls.map((u) => u.url)).toEqual([
            "https://amazon.com",
            "https://shop.com",
            "https://smile.amazon.com",
        ]);
        expect(plan.actions.find((a) => a.field === "AutofillUrls").kind).toBe("Union");
    });

    test("passkeys are unioned by key id", () => {
        const primary = loginItem("1", { title: "Amazon", username: "bob", password: "pw", passkeys: [passkey("k1"), passkey("k2")] });
        const secondary = loginItem("2", { title: "Amazon", username: "bob", password: "pw", passkeys: [passkey("k2"), passkey("k3")] });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(loginOf(plan.merged_item).passkeys.map((p) => p.key_id)).toEqual(["k1", "k2", "k3"]);
    });


    test("extra fields same name different value keeps both with source title", () => {
        const primary = noteItem("1", { title: "Amazon", extraFields: [{ name: "Router", type: "Text", value: "1.2.3.4" }] });
        const secondary = noteItem("2", { title: "Amazon", extraFields: [{ name: "Router", type: "Text", value: "5.6.7.8" }] });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(extraFieldsOf(plan.merged_item)).toEqual([
            { name: "Router", content: { Text: "1.2.3.4" } },
            { name: "Amazon - Router", content: { Text: "5.6.7.8" } },
        ]);
    });

    test("conflicting note is preserved as custom field", () => {
        const primary = noteItem("1", { title: "Amazon", note: "primary note" });
        const secondary = noteItem("2", { title: "Amazon", note: "secondary note" });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(plan.merged_item.note).toBe("primary note");
        expect(plan.merged_item.extra_fields).toEqual([{ name: "Amazon - Note", content: { Text: "secondary note" } }]);
    });

    test("credit card fields are merged individually", () => {
        const primary = creditCardItem("1", { title: "Main card", number: "4242", pin: "1234" });
        const secondary = creditCardItem("2", { title: "Old card", number: "1111", pin: "9999" });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(plan.merged_item.content.CreditCard.number).toBe("4242");
        expect(plan.merged_item.content.CreditCard.pin).toBe("1234");
        expect(plan.merged_item.extra_fields).toEqual([
            { name: "Old card - Number", content: { Hidden: "1111" } },
            { name: "Old card - PIN", content: { Hidden: "9999" } },
        ]);
        expect(plan.actions.find((a) => a.field === "CardNumber").kind).toBe("ConflictToCustomField");
    });

    test("empty credit card field is filled from secondary", () => {
        const primary = creditCardItem("1", { title: "Main card" });
        const secondary = creditCardItem("2", { title: "Old card", number: "1111" });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(plan.merged_item.content.CreditCard.number).toBe("1111");
        expect(plan.merged_item.extra_fields).toHaveLength(0);
        expect(plan.actions.find((a) => a.field === "CardNumber").kind).toBe("TakeSecondary");
    });

    test("wifi fields are merged individually", () => {
        const primary = wifiItem("1", { title: "Home", ssid: "MyWifi", password: "pw1", security: "WPA2" });
        const secondary = wifiItem("2", { title: "Home 2", ssid: "MyWifi", password: "pw2", security: "WPA3" });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(plan.merged_item.content.Wifi.ssid).toBe("MyWifi");
        expect(plan.merged_item.content.Wifi.password).toBe("pw1");
        expect(plan.merged_item.content.Wifi.security).toBe("WPA2");
        expect(plan.merged_item.extra_fields).toEqual([
            { name: "Home 2 - Password", content: { Hidden: "pw2" } },
            { name: "Home 2 - Security", content: { Hidden: "WPA3" } },
        ]);
        expect(plan.actions.find((a) => a.field === "WifiPassword").kind).toBe("ConflictToCustomField");
    });

    test("custom item sections are unioned with conflicting fields source named", () => {
        const primary = customItem("1", { title: "Main card", fields: [{ name: "Number", type: "Text", value: "1111" }] });
        const secondary = customItem("2", { title: "Old card", fields: [{ name: "Number", type: "Text", value: "2222" }] });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(plan.merged_item.content.Custom.sections[0].section_fields).toEqual([
            { name: "Number", content: { Text: "1111" } },
            { name: "Old card - section.Number", content: { Text: "2222" } },
        ]);
        expect(plan.actions.find((a) => a.field === "Section").kind).toBe("Union");
    });

    test("different item types are rejected", () => {
        const primary = loginItem("1", { title: "Amazon", username: "bob", password: "pw" });
        const secondary = noteItem("2", { title: "Amazon" });

        expect(() => plan_item_merge_wasm({ primary, secondary })).toThrow(/Cannot merge/);
    });

    test("three item group folds in visual order", () => {
        const primary = loginItem("1", {
            title: "Amazon",
            username: "bob",
            password: "pw",
            totpUri: "otpauth://totp/primary",
            urls: ["https://amazon.com"],
        });
        const secondary1 = loginItem("2", {
            title: "Amazon 2",
            username: "bobby",
            password: "pw2",
            totpUri: "otpauth://totp/secondary-1",
            urls: ["https://smile.amazon.com"],
        });
        const secondary2 = loginItem("3", {
            title: "Amazon 3",
            username: "bobbie",
            password: "pw3",
            totpUri: "otpauth://totp/secondary-2",
            urls: ["https://shop.com"],
        });

        const group = plan_group_merge_wasm({ primary, secondaries: [secondary1, secondary2] });

        expect(group.secondary_plans).toHaveLength(2);
        expect(loginOf(group.merged_item).urls).toEqual(["https://amazon.com", "https://smile.amazon.com", "https://shop.com"]);
        expect(loginOf(group.merged_item).autofill_urls.map((u) => u.url)).toEqual([
            "https://amazon.com",
            "https://smile.amazon.com",
            "https://shop.com",
        ]);
        expect(loginOf(group.merged_item).totp_uri).toBe("otpauth://totp/primary");
        expect(group.merged_item.extra_fields.map((f) => f.name)).toEqual([
            "Amazon 2 - Username",
            "Amazon 2 - Password",
            "Amazon 2 - TOTP",
            "Amazon 3 - Username",
            "Amazon 3 - Password",
            "Amazon 3 - TOTP",
        ]);
    });

    test("identical items produce an unchanged merge", () => {
        const primary = loginItem("1", {
            title: "Amazon",
            username: "bob",
            password: "pw",
            totpUri: "otpauth://totp/x",
            urls: ["https://amazon.com"],
            passkeys: [passkey("k1")],
        });
        const secondary = loginItem("2", {
            title: "Amazon",
            username: "bob",
            password: "pw",
            totpUri: "otpauth://totp/x",
            urls: ["https://amazon.com"],
            passkeys: [passkey("k1")],
        });

        const plan = plan_item_merge_wasm({ primary, secondary });

        expect(plan.merged_item.title).toBe("Amazon");
        expect(plan.merged_item.extra_fields).toHaveLength(0);
        expect(plan.actions.every((a) => a.kind === "Identical")).toBe(true);
    });
});
