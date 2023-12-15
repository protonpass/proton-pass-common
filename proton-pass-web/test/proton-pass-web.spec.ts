import { describe, expect, test } from "bun:test";
import * as packageJSON from "./pkg/package.json";

import {
  detect_credit_card_type,
  generate_passphrase,
  library_version,
  random_words,
} from "./pkg/proton_pass_web.js";

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

  test("Should detect CC", () => {
    const cardType = detect_credit_card_type("4000056655665556");
    expect(cardType).toEqual("Visa");
  });
});
