import { describe, expect, test } from "bun:test";


import {
    entry_from_uri,
    WebTotpGenerator,
    WasmAuthenticatorCodeResponse,
} from "./pkg/worker";


const delay = async (time: number) => await new Promise(resolve => setTimeout(resolve, time))

describe("ProtonAuthenticatorWeb WASM generator", () => {
    test("Can generate codes", async () => {
        const uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        const entry = entry_from_uri(uri);

        const period = 50;
        const timeProvider = () => BigInt(1739284795);
        const generator = new WebTotpGenerator(period, timeProvider);

        const generated = [];
        const handle = await generator.start([entry], (codes: [WasmAuthenticatorCodeResponse]) => {
            generated.push(codes);
        });

        const times = 3;
        await delay(period * times);
        expect(generated.length).toEqual(times);
        handle.cancel();
        await delay(period * 2);
        expect(generated.length).toEqual(times);
    });
});
