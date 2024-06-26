import { describe, expect, test } from "bun:test";
import * as packageJSON from "./pkg/package.json";

import {
    generate_passphrase,
    library_version,
    random_words,
} from "./pkg/password";

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
});