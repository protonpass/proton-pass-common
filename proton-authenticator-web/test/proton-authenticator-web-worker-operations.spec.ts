import { describe, expect, test } from "bun:test";
import * as packageJSON from "./pkg/package.json";

import {
    calculate_operations,
    entry_from_uri,
    WasmRemoteEntry,
    WasmLocalEntry,
} from "./pkg/worker";

const newEntry = (label: string, secret: string) =>
    entry_from_uri(`otpauth://totp/${label}?secret=${secret}&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15`);

describe("ProtonAuthenticatorWeb WASM diff", () => {
    test("Can handle empty lists", () => {
        const res = calculate_operations([], []);
        expect(res).toBeEmpty();
    });

    test("Does not return anything in case no differences", () => {
        const entry = newEntry("LABEL", "SECRET");
        const remote: WasmRemoteEntry[] = [
            {entry: entry, remote_id: "ID"}
        ];
        const local: WasmLocalEntry[] = [
            {entry: entry, state: "Synced"}
        ];

        const res = calculate_operations(remote, local);
        expect(res).toBeEmpty();
    });

    test("Remote entry not present in local returns upsert", () => {
        const entry = newEntry("LABEL", "SECRET");
        const remoteId = "REMOTE_ID";
        const remote: WasmRemoteEntry[] = [
            {entry: entry, remote_id: remoteId}
        ];
        const local: WasmLocalEntry[] = [];

        const res = calculate_operations(remote, local);
        expect(res.length).toEqual(1);
        expect(res[0].entry).toEqual(entry);
        expect(res[0].operation).toEqual("Upsert");
        expect(res[0].remote_id).toEqual(remoteId);
    });

    test("Local entry pending to be pushed not present in remote returns push", () => {
        const entry = newEntry("LABEL", "SECRET");
        const remote: WasmRemoteEntry[] = [];
        const local: WasmLocalEntry[] = [
            {entry: entry, state: "PendingSync"}
        ];

        const res = calculate_operations(remote, local);
        expect(res.length).toEqual(1);
        expect(res[0].entry).toEqual(entry);
        expect(res[0].operation).toEqual("Push");
        expect(res[0].remote_id).toBeUndefined();
    });
});