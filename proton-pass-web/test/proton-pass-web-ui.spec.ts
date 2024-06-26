import { describe, expect, test } from "bun:test";
import * as packageJSON from "./pkg/package.json";

import {
    detect_credit_card_type,
    get_domain,
    get_root_domain,
    library_version
} from "./pkg/ui";

describe("ProtonPassWeb WASM", () => {
    test("Library version", () => {
        expect(library_version()).toEqual(packageJSON.version);
    });

    test("Should detect CC", () => {
        const cardType = detect_credit_card_type("4000056655665556");
        expect(cardType).toEqual("Visa");
    });

    test("Can extract root domain", () => {
        const response = get_root_domain("https://test.example.com");
        expect(response).toEqual("example.com");
    });

    test("Can extract domain domain", () => {
        const response = get_domain("https://test.example.com/path?key=value");
        expect(response).toEqual("test.example.com");
    });
});
