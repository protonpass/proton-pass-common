use proton_pass_common::sshkey::{generate_ssh_key, validate_private_key, validate_public_key, SshKeyType};

#[test]
fn test_validate_valid_ed25519_public_key() {
    let valid_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rV/7xtXmXKm8zR0K1RpOFvC1mPfVgKjG7fLqJl5zp test@example.com";
    assert!(validate_public_key(valid_key).is_ok());
}

#[test]
fn test_validate_valid_rsa_public_key() {
    let key_pair = generate_ssh_key(
        "Test".to_string(),
        "test@example.com".to_string(),
        SshKeyType::RSA2048,
        None,
    )
    .unwrap();
    assert!(validate_public_key(&key_pair.public_key).is_ok());
}

#[test]
fn test_validate_invalid_public_key_format() {
    let invalid_key = "invalid-key-format";
    assert!(validate_public_key(invalid_key).is_err());
}

#[test]
fn test_validate_empty_public_key() {
    let empty_key = "";
    assert!(validate_public_key(empty_key).is_err());
}

#[test]
fn test_validate_malformed_public_key() {
    let malformed_key = "ssh-ed25519 not-base64-data test@example.com";
    assert!(validate_public_key(malformed_key).is_err());
}

#[test]
fn test_validate_valid_private_key_openssh_format() {
    let key_pair = generate_ssh_key(
        "Test".to_string(),
        "test@example.com".to_string(),
        SshKeyType::Ed25519,
        None,
    )
    .unwrap();

    assert!(validate_private_key(&key_pair.private_key).is_ok());
}

#[test]
fn test_validate_invalid_private_key() {
    let invalid_key = "-----BEGIN PRIVATE KEY-----\ninvalid data\n-----END PRIVATE KEY-----";
    assert!(validate_private_key(invalid_key).is_err());
}

#[test]
fn test_validate_empty_private_key() {
    let empty_key = "";
    assert!(validate_private_key(empty_key).is_err());
}

#[test]
fn test_generate_ed25519_key_without_passphrase() {
    let result = generate_ssh_key(
        "John Doe".to_string(),
        "john@example.com".to_string(),
        SshKeyType::Ed25519,
        None,
    );

    assert!(result.is_ok());
    let key_pair = result.unwrap();

    // Check public key format
    assert!(key_pair.public_key.starts_with("ssh-ed25519"));
    assert!(key_pair.public_key.contains("John Doe <john@example.com>"));

    // Check private key format
    assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));
    assert!(key_pair.private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(key_pair.private_key.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));

    // Validate the generated keys
    assert!(validate_public_key(&key_pair.public_key).is_ok());
    assert!(validate_private_key(&key_pair.private_key).is_ok());
}

#[test]
fn test_generate_ed25519_key_with_passphrase() {
    let result = generate_ssh_key(
        "Jane Doe".to_string(),
        "jane@example.com".to_string(),
        SshKeyType::Ed25519,
        Some("my-secure-passphrase".to_string()),
    );

    assert!(result.is_ok());
    let key_pair = result.unwrap();

    // Check public key format
    assert!(key_pair.public_key.starts_with("ssh-ed25519"));
    assert!(key_pair.public_key.contains("Jane Doe <jane@example.com>"));

    // Check private key format (encrypted keys also have OPENSSH PRIVATE KEY header)
    assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));

    // Validate the generated keys
    assert!(validate_public_key(&key_pair.public_key).is_ok());
    assert!(validate_private_key(&key_pair.private_key).is_ok());
}

#[test]
fn test_generate_rsa2048_key_without_passphrase() {
    let result = generate_ssh_key(
        "Alice".to_string(),
        "alice@example.com".to_string(),
        SshKeyType::RSA2048,
        None,
    );

    assert!(result.is_ok());
    let key_pair = result.unwrap();

    // Check public key format
    assert!(key_pair.public_key.starts_with("ssh-rsa"));
    assert!(key_pair.public_key.contains("Alice <alice@example.com>"));

    // Check private key format
    assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));

    // Validate the generated keys
    assert!(validate_public_key(&key_pair.public_key).is_ok());
    assert!(validate_private_key(&key_pair.private_key).is_ok());
}

#[test]
fn test_generate_all_key_types() {
    let key_types = vec![
        SshKeyType::RSA2048,
        // SshKeyType::RSA4096, // Too slow
        SshKeyType::Ed25519,
    ];

    for key_type in key_types {
        let result = generate_ssh_key("Test User".to_string(), "test@example.com".to_string(), key_type, None);

        assert!(result.is_ok(), "Failed to generate key");
        let key_pair = result.unwrap();

        // Ensure both keys are valid
        assert!(validate_public_key(&key_pair.public_key).is_ok(), "Invalid public key");
        assert!(
            validate_private_key(&key_pair.private_key).is_ok(),
            "Invalid private key"
        );
    }
}

#[test]
fn test_generated_keys_are_unique() {
    let key_pair1 = generate_ssh_key(
        "User1".to_string(),
        "user1@example.com".to_string(),
        SshKeyType::Ed25519,
        None,
    )
    .unwrap();

    let key_pair2 = generate_ssh_key(
        "User2".to_string(),
        "user2@example.com".to_string(),
        SshKeyType::Ed25519,
        None,
    )
    .unwrap();

    // Keys should be different
    assert_ne!(key_pair1.public_key, key_pair2.public_key);
    assert_ne!(key_pair1.private_key, key_pair2.private_key);
}

#[test]
fn test_comment_included_in_public_key() {
    let name = "Test Name";
    let email = "test@domain.com";
    let key_pair = generate_ssh_key(name.to_string(), email.to_string(), SshKeyType::Ed25519, None).unwrap();

    let expected_comment = format!("{} <{}>", name, email);
    assert!(key_pair.public_key.contains(&expected_comment));
}
