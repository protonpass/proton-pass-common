import {describe, expect, test} from "bun:test";

import {
    import_from_2fas, import_from_ente_encrypted, import_from_pass_zip, WasmAuthenticatorEntryModel
} from "./pkg/worker";

import {readFileSync} from "fs";
import {fileURLToPath} from "url";
import path from "path";

function getFilePath(filename: string): string {
    // @ts-ignore
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const basePath = path.resolve(__dirname, "../../proton-authenticator/test_data/authenticator");
    return path.join(basePath, filename);
}

function loadFile(filename: string): string {
    return readFileSync(getFilePath(filename), "utf8");
}

function loadFileBytes(filename: string): Buffer {
    return readFileSync(getFilePath(filename));
}

describe("ProtonAuthenticatorWeb WASM importer", () => {
    describe("2FAS", () => {
        const validate = (entries: WasmAuthenticatorEntryModel[]): void => {
            expect(entries.length).toEqual(2);

            expect(entries[0].entry_type).toEqual("Totp");
            expect(entries[0].name).toEqual("mylabeldefault");
            expect(entries[0].period).toEqual(30);

            expect(entries[1].entry_type).toEqual("Steam");
            expect(entries[1].name).toEqual("Steam");
            expect(entries[1].period).toEqual(30);
        };

        test("Can import decrypted", () => {
            const contents = loadFile("2fas/decrypted.2fas");
            const imported = import_from_2fas(contents, null);

            expect(imported.errors).toBeEmpty();
            validate(imported.entries);
        });
        test("Can import encrypted", () => {
            const contents = loadFile("2fas/encrypted.2fas");
            const imported = import_from_2fas(contents, "test");

            expect(imported.errors).toBeEmpty();
            validate(imported.entries);
        });
        test("Throws error with incorrect password", () => {
            const contents = loadFile("2fas/encrypted.2fas");

            try {
                import_from_2fas(contents, "WRONG_PASSWORD");
            } catch (e) {
                expect(e.message).toEqual("BadPassword");
            }
        });
    });

    describe("Proton Pass", () => {
        test("Can import pass zip file", () => {
            const content = loadFileBytes("pass/PassExport.zip");
            const imported = import_from_pass_zip(content);
            expect(imported.entries.length).toEqual(7);
            expect(imported.errors.length).toEqual(1);
        });
    });

    describe("Ente", () => {
        test("Can import encrypted backup", () => {
            const content = loadFile("ente/encrypted.lowcomplexity.txt");
            const password = loadFile("ente/password");
            const imported = import_from_ente_encrypted(content, password);
            expect(imported.entries.length).toEqual(2);
            expect(imported.errors.length).toEqual(1);
        });
    });
});
