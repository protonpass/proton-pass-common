import { describe, expect, test } from "bun:test";
import * as packageJSON from "./pkg/package.json";

import {
    decrypt_entries,
    deserialize_entries,
    encrypt_entries,
    emit_log,
    entry_from_uri,
    generate_code,
    generate_key,
    get_totp_parameters,
    library_version,
    new_steam_entry_from_params,
    register_authenticator_logger,
    serialize_entries,
    update_entry,
    WasmAuthenticatorEntryUpdateContents,
    WasmIssuerMapper
} from "./pkg/worker";

describe("ProtonAuthenticatorWeb WASM", () => {
    test("Library version", () => {
        expect(library_version()).toEqual(packageJSON.version);
    });

    test("Can parse a TOTP uri", () => {
        const uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry = entry_from_uri(uri);

        expect(entry.period).toEqual(15);
        expect(entry.entry_type).toEqual("Totp");
        expect(entry.name).toEqual("MYLABEL");
        expect(entry.note).toBeUndefined();
        expect(entry.secret).toEqual("MYSECRET");
    });

    test("ID is persisted when serializing and deserializing TOTP uri", () => {
        const uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry = entry_from_uri(uri);

        const entry_id = entry.id;
        expect(entry_id).not.toBeEmpty();

        const serialized = serialize_entries([entry]);
        expect(serialized.length).toEqual(1);

        const deserialized = deserialize_entries(serialized);
        expect(deserialized.length).toEqual(1);

        // Check that ID is preserved
        const deserializedEntry = deserialized[0];
        expect(deserializedEntry.id).toEqual(entry_id);
    });

    test("Steam entry name is preserved when serializing and deserializing", () => {
        const name = "MySteamEntry";
        const note = "My note";
        const entry = new_steam_entry_from_params({
            name: name,
            secret: "STEAMKEY",
            note: note,
        });

        const serialized = serialize_entries([entry]);
        expect(serialized.length).toEqual(1);

        const deserialized = deserialize_entries(serialized);
        expect(deserialized.length).toEqual(1);

        // Check that name and note are preserved
        const deserializedEntry = deserialized[0];
        expect(deserializedEntry.name).toEqual(name);
        expect(deserializedEntry.note).toEqual(note);
    });

    test("Can update entry", () => {
        const uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry = entry_from_uri(uri);
        const entryId = entry.id;

        const update: WasmAuthenticatorEntryUpdateContents = {
            name: "NEW_NAME",
            secret: "NEW_SECRET",
            issuer: "NEW_ISSUER",
            algorithm: "SHA1",
            digits: 4,
            period: 18,
            note: "NEW_NOTE",
            entry_type: "Totp",
        };
        const updated = update_entry(entry, update);
        expect(updated.name).toEqual(update.name);
        expect(updated.note).toEqual(update.note);
        expect(updated.issuer).toEqual(update.issuer);
        expect(updated.period).toEqual(update.period);
        expect(updated.id).toEqual(entryId);

        const totpParams = get_totp_parameters(updated);
        expect(totpParams.algorithm).toEqual(update.algorithm);
        expect(totpParams.digits).toEqual(update.digits);
        expect(totpParams.period).toEqual(update.period);

    });

    test("Can convert totp to steam entry", () => {
        const uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry = entry_from_uri(uri);
        const entryId = entry.id;

        const update: WasmAuthenticatorEntryUpdateContents = {
            name: "NEW_NAME",
            secret: "STEAMKEY",
            note: "NEW_NOTE",

            // Ignored fields
            issuer: "NEW_ISSUER",
            algorithm: "SHA512",
            digits: 4,
            period: 18,
            entry_type: "Steam",
        };
        const updated = update_entry(entry, update);
        expect(updated.id).toEqual(entryId); // ID is preserved
        expect(updated.name).toEqual(update.name); // Name is updated
        expect(updated.note).toEqual(update.note); // Note is updated

        expect(updated.issuer).toEqual("Steam"); // Note how the update param was ignored
        expect(updated.period).toEqual(30); // Note how the period param was ignored


        const totpParams = get_totp_parameters(updated);
        expect(totpParams.algorithm).toEqual("SHA1"); // Algorithm is ignored
        expect(totpParams.digits).toEqual(5); // Digits are ignored
        expect(totpParams.period).toEqual(30); // Period is ignored

    });

    test("Can get TOTP params", () => {
        const uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry = entry_from_uri(uri);

        const params = get_totp_parameters(entry);

        expect(params.period).toEqual(15);
        expect(params.digits).toEqual(8);
        expect(params.secret).toEqual("MYSECRET");
        expect(params.algorithm).toEqual("SHA256")
        expect(params.issuer).toEqual("MYISSUER")
    });

    test("Can generate a TOTP code", () => {
        const uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry = entry_from_uri(uri);

        const code = generate_code(entry, BigInt(1739284795));
        expect(code.current_code).toEqual("44326356");
        expect(code.next_code).toEqual("14336450");
    });

    test("Can generate a key", () => {
        const key = generate_key();
        expect(key.length).toEqual(32);
    });

    test("Can encrypt and decrypt", () => {
        const uri1 = "otpauth://totp/MYLABEL1?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry1 = entry_from_uri(uri1);
        const uri2 = "otpauth://totp/MYLABEL2?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry2 = entry_from_uri(uri2);

        const key = generate_key();
        const encrypted = encrypt_entries([entry1, entry2], key);
        expect(encrypted.length).toEqual(2);

        const decrypted = decrypt_entries(encrypted, key);
        expect(decrypted.length).toEqual(2);

        expect(decrypted[0].name).toEqual("MYLABEL1");
        expect(decrypted[1].name).toEqual("MYLABEL2");
    });

    test("Can register a logger", () => {
        const records = [];
        register_authenticator_logger((level, message) => {
            records.push({level, message});
        });

        const message1 = "trace message";
        emit_log("Trace", message1);
        const message2 = "debug message";
        emit_log("Debug", message2);
        const message3 = "info message";
        emit_log("Info", message3);
        const message4 = "warn message";
        emit_log("Warn", message4);
        const message5 = "error message";
        emit_log("Error", message5);

        expect(records.length).toEqual(5);

        expect(records[0].level).toEqual("trace");
        expect(records[0].message).toEqual(message1);

        expect(records[1].level).toEqual("debug");
        expect(records[1].message).toEqual(message2);

        expect(records[2].level).toEqual("info");
        expect(records[2].message).toEqual(message3);

        expect(records[3].level).toEqual("warn");
        expect(records[3].message).toEqual(message4);

        expect(records[4].level).toEqual("error");
        expect(records[4].message).toEqual(message5);
    });

    test("Can get issuer info", () => {
        const mapper = new WasmIssuerMapper();
        const nonExistantInfo = mapper.get_issuer_info("NONEXISTANT");
        expect(nonExistantInfo).toBeUndefined();

        const protonInfo = mapper.get_issuer_info("Protonmail");
        expect(protonInfo).toEqual({
            icon_url: "https://proton.me/favicons/apple-touch-icon.png",
            domain: "proton.me"
        });

        const wikipediaInfo = mapper.get_issuer_info("Wikipedia");
        expect(wikipediaInfo).toEqual({
            icon_url: "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://wikipedia.org&size=256",
            domain: "wikipedia.org"
        });
    });
});
