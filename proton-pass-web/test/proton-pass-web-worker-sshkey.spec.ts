import { describe, expect, test } from "bun:test";
import * as packageJSON from "./pkg/package.json";

import {
    decrypt_private_ssh_key,
    generate_ssh_key_pair,
    library_version,
    validate_private_ssh_key,
    validate_public_ssh_key,
} from "./pkg/worker/proton_pass_web";

describe("ProtonPassWeb WASM - SSH Key Management", () => {
    test("Library version", () => {
        expect(library_version()).toEqual(packageJSON.version);
    });

    test("Should validate a valid Ed25519 public key", () => {
        const validKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rV/7xtXmXKm8zR0K1RpOFvC1mPfVgKjG7fLqJl5zp test@example.com";
        expect(() => validate_public_ssh_key(validKey)).not.toThrow();
    });

    test("Should reject an invalid public key", () => {
        const invalidKey = "invalid-ssh-key";
        expect(() => validate_public_ssh_key(invalidKey)).toThrow();
    });

    test("Should reject an empty public key", () => {
        const emptyKey = "";
        expect(() => validate_public_ssh_key(emptyKey)).toThrow();
    });

    test("Should reject a malformed public key", () => {
        const malformedKey = "ssh-ed25519 not-base64-data test@example.com";
        expect(() => validate_public_ssh_key(malformedKey)).toThrow();
    });

    test("Should generate an Ed25519 SSH key pair without passphrase", () => {
        const keyPair = generate_ssh_key_pair(
            "Test User <test@example.com>",
            "Ed25519",
            undefined
        );

        expect(keyPair).toBeDefined();
        expect(keyPair.public_key).toContain("ssh-ed25519");
        expect(keyPair.public_key).toContain("Test User <test@example.com>");
        expect(keyPair.private_key).toContain("OPENSSH PRIVATE KEY");
        expect(keyPair.private_key).toContain("-----BEGIN OPENSSH PRIVATE KEY-----");
        expect(keyPair.private_key).toContain("-----END OPENSSH PRIVATE KEY-----");
    });

    test("Should generate an Ed25519 SSH key pair with passphrase", () => {
        const keyPair = generate_ssh_key_pair(
            "Test User <test@example.com>",
            "Ed25519",
            "my-secure-passphrase"
        );

        expect(keyPair).toBeDefined();
        expect(keyPair.public_key).toContain("ssh-ed25519");
        expect(keyPair.public_key).toContain("Test User <test@example.com>");
        expect(keyPair.private_key).toContain("OPENSSH PRIVATE KEY");
    });

    test("Should generate an RSA2048 SSH key pair", () => {
        const keyPair = generate_ssh_key_pair(
            "Alice <alice@example.com>",
            "RSA2048",
            undefined
        );

        expect(keyPair).toBeDefined();
        expect(keyPair.public_key).toContain("ssh-rsa");
        expect(keyPair.public_key).toContain("Alice <alice@example.com>");
        expect(keyPair.private_key).toContain("OPENSSH PRIVATE KEY");
    });

    test("Generated public keys should be valid", () => {
        const keyPair = generate_ssh_key_pair(
            "Test <test@example.com>",
            "Ed25519",
            undefined
        );

        expect(() => validate_public_ssh_key(keyPair.public_key)).not.toThrow();
    });

    test("Generated private keys should be valid", () => {
        const keyPair = generate_ssh_key_pair(
            "Test <test@example.com>",
            "Ed25519",
            undefined
        );

        expect(() => validate_private_ssh_key(keyPair.private_key)).not.toThrow();
    });

    test("Should validate generated RSA2048 keys", () => {
        const keyPair = generate_ssh_key_pair(
            "Test <test@example.com>",
            "RSA2048",
            undefined
        );

        expect(() => validate_public_ssh_key(keyPair.public_key)).not.toThrow();
        expect(() => validate_private_ssh_key(keyPair.private_key)).not.toThrow();
    });

    test("Should reject invalid private key", () => {
        const invalidKey = "-----BEGIN PRIVATE KEY-----\ninvalid data\n-----END PRIVATE KEY-----";
        expect(() => validate_private_ssh_key(invalidKey)).toThrow();
    });

    test("Should generate unique keys", () => {
        const keyPair1 = generate_ssh_key_pair(
            "User1 <user1@example.com>",
            "Ed25519",
            undefined
        );
        const keyPair2 = generate_ssh_key_pair(
            "User2 <user2@example.com>",
            "Ed25519",
            undefined
        );

        expect(keyPair1.public_key).not.toEqual(keyPair2.public_key);
        expect(keyPair1.private_key).not.toEqual(keyPair2.private_key);
    });

    test("Should include comment in public key", () => {
        const comment = "John Doe <john@example.com>";
        const keyPair = generate_ssh_key_pair(
            comment,
            "Ed25519",
            undefined
        );

        expect(keyPair.public_key).toContain(comment);
    });

    test("Should decrypt RSA2048 key with correct passphrase", () => {
        const passphrase = "test-passphrase";
        const keyPair = generate_ssh_key_pair(
            "Test User <test@example.com>",
            "RSA2048",
            passphrase
        );

        const decrypted = decrypt_private_ssh_key(keyPair.private_key, passphrase);

        expect(decrypted).toContain("OPENSSH PRIVATE KEY");
        expect(() => validate_private_ssh_key(decrypted)).not.toThrow();
    });

    test("Should decrypt Ed25519 key with correct passphrase", () => {
        const passphrase = "secure-password";
        const keyPair = generate_ssh_key_pair(
            "Alice <alice@example.com>",
            "Ed25519",
            passphrase
        );

        const decrypted = decrypt_private_ssh_key(keyPair.private_key, passphrase);

        expect(decrypted).toContain("OPENSSH PRIVATE KEY");
        expect(() => validate_private_ssh_key(decrypted)).not.toThrow();
    });

    test("Should throw on wrong passphrase", () => {
        const passphrase = "correct-password";
        const keyPair = generate_ssh_key_pair(
            "Bob <bob@example.com>",
            "Ed25519",
            passphrase
        );

        expect(() => decrypt_private_ssh_key(keyPair.private_key, "wrong-password")).toThrow();
    });

    test("Should throw on invalid encrypted key", () => {
        const invalidKey = "invalid-private-key-data";
        expect(() => decrypt_private_ssh_key(invalidKey, "password")).toThrow();
    });

    test("Decrypted key should be valid and unencrypted", () => {
        const passphrase = "test-pass";
        const keyPair = generate_ssh_key_pair(
            "Charlie <charlie@example.com>",
            "Ed25519",
            passphrase
        );

        const decrypted = decrypt_private_ssh_key(keyPair.private_key, passphrase);

        expect(() => validate_private_ssh_key(decrypted)).not.toThrow();

        const redecrypted = decrypt_private_ssh_key(decrypted, "any-password");
        expect(redecrypted).toEqual(decrypted);
    });
});

