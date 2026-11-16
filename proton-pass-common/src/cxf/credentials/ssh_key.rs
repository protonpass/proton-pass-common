use credential_exchange_format::{
    B64Url, Credential, CustomFieldsCredential, EditableField, EditableFieldValue, SshKeyCredential,
};
use ed25519_dalek::SigningKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use proton_pass_types::SshKeyItem;
use ssh_key::LineEnding;
use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, Ed25519Keypair, KeypairData, RsaKeypair};

use crate::cxf::{CxfCredential, CxfWarning, CxfWarningKind, ProtonExtension};

pub(crate) const PUBLIC_KEY_FIELD_LABEL: &str = "public_key";

fn keypair_to_pkcs8_der(key_data: &KeypairData) -> Option<Vec<u8>> {
    match key_data {
        KeypairData::Ed25519(keypair) => {
            let signing_key = SigningKey::try_from(keypair).ok()?;
            signing_key.to_pkcs8_der().ok().map(|doc| doc.as_bytes().to_vec())
        }
        KeypairData::Rsa(keypair) => {
            let private_key = rsa::PrivateKey::try_from(keypair).ok()?;
            private_key.to_pkcs8_der().ok().map(|doc| doc.as_bytes().to_vec())
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) => {
            let secret = p256::SecretKey::from_slice(private.as_slice()).ok()?;
            secret.to_pkcs8_der().ok().map(|doc| doc.as_bytes().to_vec())
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) => {
            let secret = p384::SecretKey::from_slice(private.as_slice()).ok()?;
            secret.to_pkcs8_der().ok().map(|doc| doc.as_bytes().to_vec())
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP521 { private, .. }) => {
            let secret = p521::SecretKey::from_slice(private.as_slice()).ok()?;
            secret.to_pkcs8_der().ok().map(|doc| doc.as_bytes().to_vec())
        }
        _ => None,
    }
}

fn pkcs8_der_to_keypair(der: &[u8]) -> Option<KeypairData> {
    if let Ok(signing_key) = SigningKey::from_pkcs8_der(der) {
        return Some(KeypairData::Ed25519(Ed25519Keypair::from(signing_key)));
    }
    if let Ok(private_key) = rsa::PrivateKey::from_pkcs8_der(der) {
        return RsaKeypair::try_from(private_key).ok().map(KeypairData::Rsa);
    }
    if let Ok(secret) = p256::SecretKey::from_pkcs8_der(der) {
        let public = secret.public_key().into();
        let private = EcdsaPrivateKey::<32>::from(secret);
        return Some(KeypairData::Ecdsa(EcdsaKeypair::NistP256 { public, private }));
    }
    if let Ok(secret) = p384::SecretKey::from_pkcs8_der(der) {
        let public = secret.public_key().into();
        let private = EcdsaPrivateKey::<48>::from(secret);
        return Some(KeypairData::Ecdsa(EcdsaKeypair::NistP384 { public, private }));
    }
    if let Ok(secret) = p521::SecretKey::from_pkcs8_der(der) {
        let public = secret.public_key().into();
        let private = EcdsaPrivateKey::<66>::from(secret);
        return Some(KeypairData::Ecdsa(EcdsaKeypair::NistP521 { public, private }));
    }
    None
}

pub(crate) fn ssh_key_to_credential(
    item: &SshKeyItem,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> Option<CxfCredential> {
    let key = match ssh_key::PrivateKey::from_openssh(&item.private_key) {
        Ok(key) => key,
        Err(_) => {
            warnings.push(CxfWarning {
                item_title: item_title.map(str::to_string),
                message: "Could not export SSH key: unrecognized or unsupported key algorithm".to_string(),
                kind: CxfWarningKind::UnsupportedCredential,
            });
            return None;
        }
    };

    let key_type = key.algorithm().to_string();

    if key.is_encrypted() {
        warnings.push(CxfWarning {
            item_title: item_title.map(str::to_string),
            message: "Could not export SSH key: the key is passphrase-protected".to_string(),
            kind: CxfWarningKind::UnsupportedCredential,
        });
        return None;
    }

    let der = match keypair_to_pkcs8_der(key.key_data()) {
        Some(der) => der,
        None => {
            warnings.push(CxfWarning {
                item_title: item_title.map(str::to_string),
                message: "Could not export SSH key: unsupported key algorithm for PKCS#8 encoding".to_string(),
                kind: CxfWarningKind::UnsupportedCredential,
            });
            return None;
        }
    };

    Some(Credential::SshKey(Box::new(SshKeyCredential {
        key_type,
        private_key: B64Url::from(der),
        key_comment: None,
        creation_date: None,
        expiry_date: None,
        key_generation_source: None,
    })))
}

pub(crate) fn public_key_to_credential(public_key: &str) -> Option<CxfCredential> {
    if public_key.is_empty() {
        return None;
    }
    Some(Credential::CustomFields(Box::new(CustomFieldsCredential {
        id: None,
        label: None,
        fields: vec![EditableFieldValue::String(EditableField {
            id: None,
            value: credential_exchange_format::EditableFieldString(public_key.to_string()).into(),
            label: Some(PUBLIC_KEY_FIELD_LABEL.to_string()),
            extensions: None,
        })],
        extensions: Vec::new(),
    })))
}

pub(crate) fn extract_public_key(cred: &CustomFieldsCredential<ProtonExtension>) -> Option<String> {
    cred.fields.iter().find_map(|field| match field {
        EditableFieldValue::String(f) if f.label.as_deref() == Some(PUBLIC_KEY_FIELD_LABEL) => {
            Some(f.value.clone().into())
        }
        _ => None,
    })
}

pub(crate) fn credential_to_ssh_key(
    cred: &SshKeyCredential<ProtonExtension>,
    public_key: String,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> Option<SshKeyItem> {
    let der: Vec<u8> = Vec::from(cred.private_key.clone());

    let Some(key_data) = pkcs8_der_to_keypair(&der) else {
        warnings.push(CxfWarning {
            item_title: item_title.map(str::to_string),
            message: "Could not import SSH private key: unsupported or malformed PKCS#8 key".to_string(),
            kind: CxfWarningKind::MalformedInput,
        });
        return None;
    };

    let private_key = match ssh_key::PrivateKey::new(key_data, "") {
        Ok(key) => match key.to_openssh(LineEnding::LF) {
            Ok(pem) => pem.to_string(),
            Err(_) => {
                warnings.push(CxfWarning {
                    item_title: item_title.map(str::to_string),
                    message: "Could not import SSH private key: failed to encode as OpenSSH".to_string(),
                    kind: CxfWarningKind::MalformedInput,
                });
                return None;
            }
        },
        Err(_) => {
            warnings.push(CxfWarning {
                item_title: item_title.map(str::to_string),
                message: "Could not import SSH private key: failed to build key".to_string(),
                kind: CxfWarningKind::MalformedInput,
            });
            return None;
        }
    };

    Some(SshKeyItem {
        private_key,
        public_key,
        sections: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_ed25519_openssh_key() -> String {
        let keypair = Ed25519Keypair::random(&mut rand::rng());
        ssh_key::PrivateKey::from(keypair)
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn generate_rsa_openssh_key() -> String {
        let keypair = RsaKeypair::random(&mut rand::rng(), 2048).unwrap();
        ssh_key::PrivateKey::new(KeypairData::Rsa(keypair), "")
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn generate_p256_openssh_key() -> String {
        let keypair = EcdsaKeypair::random(&mut rand::rng(), ssh_key::EcdsaCurve::NistP256).unwrap();
        ssh_key::PrivateKey::new(KeypairData::Ecdsa(keypair), "")
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn generate_passphrase_protected_openssh_key() -> String {
        let keypair = Ed25519Keypair::random(&mut rand::rng());
        let key = ssh_key::PrivateKey::from(keypair);
        key.encrypt(&mut rand::rng(), "hunter2")
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[test]
    fn ed25519_private_key_round_trips_as_pkcs8_der() {
        let private_key = generate_ed25519_openssh_key();
        let item = SshKeyItem {
            private_key,
            public_key: "ssh-ed25519 AAAA".to_string(),
            sections: Vec::new(),
        };
        let mut warnings = Vec::new();
        let cred = ssh_key_to_credential(&item, None, &mut warnings).unwrap();
        let Credential::SshKey(cred) = cred else {
            panic!("expected ssh key credential")
        };
        assert!(warnings.is_empty());

        let der: Vec<u8> = Vec::from(cred.private_key.clone());
        pkcs8::PrivateKeyInfoRef::try_from(der.as_slice()).expect("private key must be valid PKCS#8 DER");

        let back = credential_to_ssh_key(&cred, item.public_key.clone(), None, &mut warnings).unwrap();
        assert!(warnings.is_empty());

        let original_key = ssh_key::PrivateKey::from_openssh(&item.private_key).unwrap();
        let round_tripped_key = ssh_key::PrivateKey::from_openssh(&back.private_key).unwrap();
        assert_eq!(
            original_key.key_data().ed25519().unwrap().private.as_ref(),
            round_tripped_key.key_data().ed25519().unwrap().private.as_ref()
        );
    }

    #[test]
    fn rsa_private_key_round_trips_as_pkcs8_der() {
        let private_key = generate_rsa_openssh_key();
        let item = SshKeyItem {
            private_key,
            public_key: "ssh-rsa AAAA".to_string(),
            sections: Vec::new(),
        };
        let mut warnings = Vec::new();
        let cred = ssh_key_to_credential(&item, None, &mut warnings).unwrap();
        let Credential::SshKey(cred) = cred else {
            panic!("expected ssh key credential")
        };
        assert!(warnings.is_empty());

        let der: Vec<u8> = Vec::from(cred.private_key.clone());
        pkcs8::PrivateKeyInfoRef::try_from(der.as_slice()).expect("private key must be valid PKCS#8 DER");

        let back = credential_to_ssh_key(&cred, item.public_key.clone(), None, &mut warnings).unwrap();
        assert!(warnings.is_empty());
        assert!(ssh_key::PrivateKey::from_openssh(&back.private_key).is_ok());
    }

    #[test]
    fn ecdsa_p256_private_key_round_trips_as_pkcs8_der() {
        let private_key = generate_p256_openssh_key();
        let item = SshKeyItem {
            private_key,
            public_key: "ecdsa-sha2-nistp256 AAAA".to_string(),
            sections: Vec::new(),
        };
        let mut warnings = Vec::new();
        let cred = ssh_key_to_credential(&item, None, &mut warnings).unwrap();
        let Credential::SshKey(cred) = cred else {
            panic!("expected ssh key credential")
        };
        assert!(warnings.is_empty());

        let der: Vec<u8> = Vec::from(cred.private_key.clone());
        pkcs8::PrivateKeyInfoRef::try_from(der.as_slice()).expect("private key must be valid PKCS#8 DER");

        let back = credential_to_ssh_key(&cred, item.public_key.clone(), None, &mut warnings).unwrap();
        assert!(warnings.is_empty());
        assert!(ssh_key::PrivateKey::from_openssh(&back.private_key).is_ok());
    }

    #[test]
    fn importing_third_party_pkcs8_der_ed25519_key_succeeds() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let der = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let cred = SshKeyCredential {
            key_type: "ssh-ed25519".to_string(),
            private_key: B64Url::from(der),
            key_comment: None,
            creation_date: None,
            expiry_date: None,
            key_generation_source: None,
        };
        let mut warnings = Vec::new();
        let item = credential_to_ssh_key(&cred, "ssh-ed25519 AAAA".to_string(), None, &mut warnings).unwrap();
        assert!(warnings.is_empty());
        assert!(ssh_key::PrivateKey::from_openssh(&item.private_key).is_ok());
    }

    #[test]
    fn passphrase_protected_key_is_excluded_with_a_specific_warning() {
        let item = SshKeyItem {
            private_key: generate_passphrase_protected_openssh_key(),
            public_key: "ssh-ed25519 AAAA".to_string(),
            sections: Vec::new(),
        };
        let mut warnings = Vec::new();
        assert!(ssh_key_to_credential(&item, None, &mut warnings).is_none());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("passphrase-protected"));
    }

    #[test]
    fn malformed_pkcs8_der_is_rejected() {
        let cred = SshKeyCredential {
            key_type: "ssh-ed25519".to_string(),
            private_key: B64Url::from(vec![1, 2, 3]),
            key_comment: None,
            creation_date: None,
            expiry_date: None,
            key_generation_source: None,
        };
        let mut warnings = Vec::new();
        assert!(credential_to_ssh_key(&cred, "public".to_string(), None, &mut warnings).is_none());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn public_key_round_trips_via_custom_fields_credential() {
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5".to_string();
        let cred = public_key_to_credential(&public_key).unwrap();
        let Credential::CustomFields(cred) = cred else {
            panic!("expected custom fields credential")
        };
        assert_eq!(extract_public_key(&cred), Some(public_key));
    }

    #[test]
    fn empty_public_key_produces_no_credential() {
        assert!(public_key_to_credential("").is_none());
    }
}
