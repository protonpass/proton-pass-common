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
    register_authenticator_logger,
    serialize_entries,
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
    });

    test("ID is persisted when serializing and deserializing TOTP uri", () => {
        register_authenticator_logger((level: string, msg: string) => {
            console.log(`[${level}] ${msg}`);
        })
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

});
