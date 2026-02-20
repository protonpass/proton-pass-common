import { describe, expect, test } from "bun:test";
import * as packageJSON from "./pkg/package.json";

import {
    generate_username,
    generate_passkey,
    generate_passphrase,
    library_version,
    random_words,
    generate_totp,
} from "./pkg/worker";

describe("ProtonPassWeb WASM", () => {
    test("Library version", () => {
        expect(library_version()).toEqual(packageJSON.version);
    });

    test("Should create passphrase", () => {
        const words = random_words(3);
        const passphrase = generate_passphrase(words, {
            separator: "Hyphens",
            capitalise: true,
            include_numbers: true,
            count: 3,
        });

        expect(passphrase).not.toBeUndefined();
    });

    test("Should generate username", () => {
        const username = generate_username({
            word_count: 3,
            include_numbers: false,
            capitalise: true,
            separator: "Hyphens",
            leetspeak: false,
            word_types: { adjectives: true, nouns: true, verbs: false },
        });

        expect(username).not.toBeUndefined();
        console.log("Generated username:", username);
    });

    test("Should generate username with all options", () => {
        const username = generate_username({
            word_count: 2,
            include_numbers: true,
            capitalise: true,
            separator: "Underscores",
            leetspeak: true,
            word_types: { adjectives: true, nouns: true, verbs: true },
        });

        expect(username).not.toBeUndefined();
        console.log("Generated username with options:", username);
    });

    test("Can generate passkey", async () => {
        const input = {
            attestation: "none",
            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "preferred",
            },
            challenge:
                "D-5y7y_E4V8NQBJrFnnhd7NCvRGhO5sBGwzfh23y8D4a_hSMyRRuTAp0hmSm6_eimM71XoYF84VUiY8e9kqavA",
            excludeCredentials: [],
            extensions: { credProps: true },
            pubKeyCredParams: [
                { alg: -7, type: "public-key" },
                { alg: -257, type: "public-key" },
            ],
            rp: { id: "webauthn.io", name: "webauthn.io" },
            user: { displayName: "uyguyhj", id: "ZFhsbmRYbG9hZw", name: "uyguyhj" },
        };
        const inputString = JSON.stringify(input);
        const response = await generate_passkey("https://webauthn.io", inputString);
        expect(response.credential).not.toBeEmpty();
        expect(response.passkey).not.toBeEmpty();
        expect(response.user_id).not.toBeEmpty();
        expect(response.key_id).not.toBeEmpty();
    });

    test("Can generate TOTP (full uri default params)", async () => {
        const uri = "otpauth://totp/some_label?secret=ABCDEFG&algorithm=SHA1&digits=6&period=30";
        // @ts-ignore
        const timestamp = 1730721205;
        const res = generate_totp(uri, BigInt(timestamp));
        expect(res.token).toEqual("103847");
        expect(res.timestamp).toEqual(timestamp);
        expect(res.totp.digits).toEqual(6);
        expect(res.totp.secret).toEqual("ABCDEFG");
        expect(res.totp.algorithm).toEqual("SHA1");
        expect(res.totp.issuer).toBeUndefined();
        expect(res.totp.label).toEqual("some_label");
        expect(res.totp.period).toEqual(30);

    });

    test("Can generate TOTP (only secret)", async () => {
        const uri = "ABCDEFG";
        // @ts-ignore
        const timestamp = 1730721205;
        const res = generate_totp(uri, BigInt(timestamp));
        expect(res.token).toEqual("103847");
        expect(res.timestamp).toEqual(timestamp);
    });

    test("Can generate TOTP (other params)", async () => {
        const uri = "otpauth://totp/some_label?secret=ABCDEFG&algorithm=SHA256&digits=8&period=10";
        // @ts-ignore
        const timestamp = 1730721205;
        const res = generate_totp(uri, BigInt(timestamp));

        expect(res.token).toEqual("72710637");
        expect(res.timestamp).toEqual(timestamp);
        expect(res.totp.digits).toEqual(8);
        expect(res.totp.secret).toEqual("ABCDEFG");
        expect(res.totp.algorithm).toEqual("SHA256");
        expect(res.totp.issuer).toBeUndefined();
        expect(res.totp.label).toEqual("some_label");
        expect(res.totp.period).toEqual(10);

    });

    test("Can generate passkey with prf", async () => {
        const input = {
            attestation: "none",
            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "preferred",
            },
            challenge:
                "D-5y7y_E4V8NQBJrFnnhd7NCvRGhO5sBGwzfh23y8D4a_hSMyRRuTAp0hmSm6_eimM71XoYF84VUiY8e9kqavA",
            excludeCredentials: [],
            extensions: { prf: {} },
            pubKeyCredParams: [
                { alg: -7, type: "public-key" },
                { alg: -257, type: "public-key" },
            ],
            rp: { id: "webauthn.io", name: "webauthn.io" },
            user: { displayName: "uyguyhj", id: "ZFhsbmRYbG9hZw", name: "uyguyhj" },
        };
        const inputString = JSON.stringify(input);
        const response = await generate_passkey("https://webauthn.io", inputString);

        const extensionResults = response.credential.client_extension_results;

        expect(extensionResults.hasOwnProperty("credProps")).toBeTrue();
        expect(extensionResults.credProps).toBeUndefined();

        const prf = extensionResults.prf;
        expect(prf).not.toBeUndefined();
        expect(prf.enabled).toBeTrue();
    });
});
