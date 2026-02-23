import { describe, expect, test } from "bun:test";
import { generate_username, library_version } from "./pkg/username";
import * as packageJSON from "./pkg/package.json";


describe("ProtonPassWeb WASM", () => {
    test("Library version", () => {
        expect(library_version()).toEqual(packageJSON.version);
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
        expect(username).toContain("-");
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
        expect(username).toContain("_");
    });

});