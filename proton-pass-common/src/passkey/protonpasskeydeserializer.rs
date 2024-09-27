use super::protonpasskey::{
    ProtonAlgorithm, ProtonInteger, ProtonKey, ProtonKeyOperation, ProtonKeyType, ProtonLabel,
    ProtonPassCredentialExtensions, ProtonPassKey, ProtonPassStoredHmacSecret, ProtonRegisteredLabelKeyOperation,
    ProtonRegisteredLabelKeyType, ProtonRegisteredLabelWithPrivateAlgorithm, ProtonValue,
};
use coset::cbor::value::Integer;
use coset::cbor::Value;
use coset::iana::KeyOperation;
use coset::{CoseKey, KeyType, Label, RegisteredLabel, RegisteredLabelWithPrivate};
use passkey::types::{Bytes, Passkey};
use passkey_types::{CredentialExtensions, StoredHmacSecret};
use std::collections::BTreeSet;
use std::ops::Deref;

impl From<ProtonPassKey> for Passkey {
    fn from(value: ProtonPassKey) -> Self {
        Passkey {
            key: CoseKey::from(value.key),
            credential_id: Bytes::from(value.credential_id),
            rp_id: value.rp_id,
            user_handle: value.user_handle.map(Bytes::from),
            counter: value.counter,
            extensions: CredentialExtensions::from(value.extensions),
        }
    }
}

impl From<ProtonKey> for CoseKey {
    fn from(value: ProtonKey) -> Self {
        let mut key_ops = BTreeSet::new();
        for op in value.key_ops {
            key_ops.insert(RegisteredLabel::from(op));
        }

        let mut params: Vec<(Label, Value)> = Vec::new();
        for (label, value) in value.params {
            params.push((Label::from(label), Value::from(value)));
        }

        CoseKey {
            kty: value.kty.into(),
            key_id: value.key_id,
            alg: value.alg.map(coset::Algorithm::from),
            key_ops,
            base_iv: value.base_iv,
            params,
        }
    }
}

impl From<ProtonRegisteredLabelKeyType> for KeyType {
    fn from(value: ProtonRegisteredLabelKeyType) -> Self {
        match value {
            ProtonRegisteredLabelKeyType::Assigned(t) => KeyType::Assigned(t.into()),
            ProtonRegisteredLabelKeyType::Text(t) => KeyType::Text(t),
        }
    }
}

impl From<ProtonKeyType> for coset::iana::KeyType {
    fn from(value: ProtonKeyType) -> Self {
        match value {
            ProtonKeyType::Reserved => coset::iana::KeyType::Reserved,
            ProtonKeyType::OKP => coset::iana::KeyType::OKP,
            ProtonKeyType::EC2 => coset::iana::KeyType::EC2,
            ProtonKeyType::RSA => coset::iana::KeyType::RSA,
            ProtonKeyType::Symmetric => coset::iana::KeyType::Symmetric,
            ProtonKeyType::HSS_LMS => coset::iana::KeyType::HSS_LMS,
            ProtonKeyType::WalnutDSA => coset::iana::KeyType::WalnutDSA,
        }
    }
}

impl From<ProtonAlgorithm> for coset::iana::Algorithm {
    fn from(value: ProtonAlgorithm) -> Self {
        match value {
            ProtonAlgorithm::RS1 => coset::iana::Algorithm::RS1,
            ProtonAlgorithm::WalnutDSA => coset::iana::Algorithm::WalnutDSA,
            ProtonAlgorithm::RS512 => coset::iana::Algorithm::RS512,
            ProtonAlgorithm::RS384 => coset::iana::Algorithm::RS384,
            ProtonAlgorithm::RS256 => coset::iana::Algorithm::RS256,
            ProtonAlgorithm::ES256K => coset::iana::Algorithm::ES256K,
            ProtonAlgorithm::HSS_LMS => coset::iana::Algorithm::HSS_LMS,
            ProtonAlgorithm::SHAKE256 => coset::iana::Algorithm::SHAKE256,
            ProtonAlgorithm::SHA_512 => coset::iana::Algorithm::SHA_512,
            ProtonAlgorithm::SHA_384 => coset::iana::Algorithm::SHA_384,
            ProtonAlgorithm::RSAES_OAEP_SHA_512 => coset::iana::Algorithm::RSAES_OAEP_SHA_512,
            ProtonAlgorithm::RSAES_OAEP_SHA_256 => coset::iana::Algorithm::RSAES_OAEP_SHA_256,
            ProtonAlgorithm::RSAES_OAEP_RFC_8017_default => coset::iana::Algorithm::RSAES_OAEP_RFC_8017_default,
            ProtonAlgorithm::PS512 => coset::iana::Algorithm::PS512,
            ProtonAlgorithm::PS384 => coset::iana::Algorithm::PS384,
            ProtonAlgorithm::PS256 => coset::iana::Algorithm::PS256,
            ProtonAlgorithm::ES512 => coset::iana::Algorithm::ES512,
            ProtonAlgorithm::ES384 => coset::iana::Algorithm::ES384,
            ProtonAlgorithm::ECDH_SS_A256KW => coset::iana::Algorithm::ECDH_SS_A256KW,
            ProtonAlgorithm::ECDH_SS_A192KW => coset::iana::Algorithm::ECDH_SS_A192KW,
            ProtonAlgorithm::ECDH_SS_A128KW => coset::iana::Algorithm::ECDH_SS_A128KW,
            ProtonAlgorithm::ECDH_ES_A256KW => coset::iana::Algorithm::ECDH_ES_A256KW,
            ProtonAlgorithm::ECDH_ES_A192KW => coset::iana::Algorithm::ECDH_ES_A192KW,
            ProtonAlgorithm::ECDH_ES_A128KW => coset::iana::Algorithm::ECDH_ES_A128KW,
            ProtonAlgorithm::ECDH_SS_HKDF_512 => coset::iana::Algorithm::ECDH_SS_HKDF_512,
            ProtonAlgorithm::ECDH_SS_HKDF_256 => coset::iana::Algorithm::ECDH_SS_HKDF_256,
            ProtonAlgorithm::ECDH_ES_HKDF_512 => coset::iana::Algorithm::ECDH_ES_HKDF_512,
            ProtonAlgorithm::ECDH_ES_HKDF_256 => coset::iana::Algorithm::ECDH_ES_HKDF_256,
            ProtonAlgorithm::SHAKE128 => coset::iana::Algorithm::SHAKE128,
            ProtonAlgorithm::SHA_512_256 => coset::iana::Algorithm::SHA_512_256,
            ProtonAlgorithm::SHA_256 => coset::iana::Algorithm::SHA_256,
            ProtonAlgorithm::SHA_256_64 => coset::iana::Algorithm::SHA_256_64,
            ProtonAlgorithm::SHA_1 => coset::iana::Algorithm::SHA_1,
            ProtonAlgorithm::Direct_HKDF_AES_256 => coset::iana::Algorithm::Direct_HKDF_AES_256,
            ProtonAlgorithm::Direct_HKDF_AES_128 => coset::iana::Algorithm::Direct_HKDF_AES_128,
            ProtonAlgorithm::Direct_HKDF_SHA_512 => coset::iana::Algorithm::Direct_HKDF_SHA_512,
            ProtonAlgorithm::Direct_HKDF_SHA_256 => coset::iana::Algorithm::Direct_HKDF_SHA_256,
            ProtonAlgorithm::EdDSA => coset::iana::Algorithm::EdDSA,
            ProtonAlgorithm::ES256 => coset::iana::Algorithm::ES256,
            ProtonAlgorithm::Direct => coset::iana::Algorithm::Direct,
            ProtonAlgorithm::A256KW => coset::iana::Algorithm::A256KW,
            ProtonAlgorithm::A192KW => coset::iana::Algorithm::A192KW,
            ProtonAlgorithm::A128KW => coset::iana::Algorithm::A128KW,
            ProtonAlgorithm::Reserved => coset::iana::Algorithm::Reserved,
            ProtonAlgorithm::A128GCM => coset::iana::Algorithm::A128GCM,
            ProtonAlgorithm::A192GCM => coset::iana::Algorithm::A192GCM,
            ProtonAlgorithm::A256GCM => coset::iana::Algorithm::A256GCM,
            ProtonAlgorithm::HMAC_256_64 => coset::iana::Algorithm::HMAC_256_64,
            ProtonAlgorithm::HMAC_256_256 => coset::iana::Algorithm::HMAC_256_256,
            ProtonAlgorithm::HMAC_384_384 => coset::iana::Algorithm::HMAC_384_384,
            ProtonAlgorithm::HMAC_512_512 => coset::iana::Algorithm::HMAC_512_512,
            ProtonAlgorithm::AES_CCM_16_64_128 => coset::iana::Algorithm::AES_CCM_16_64_128,
            ProtonAlgorithm::AES_CCM_16_64_256 => coset::iana::Algorithm::AES_CCM_16_64_256,
            ProtonAlgorithm::AES_CCM_64_64_128 => coset::iana::Algorithm::AES_CCM_64_64_128,
            ProtonAlgorithm::AES_CCM_64_64_256 => coset::iana::Algorithm::AES_CCM_64_64_256,
            ProtonAlgorithm::AES_MAC_128_64 => coset::iana::Algorithm::AES_MAC_128_64,
            ProtonAlgorithm::AES_MAC_256_64 => coset::iana::Algorithm::AES_MAC_256_64,
            ProtonAlgorithm::ChaCha20Poly1305 => coset::iana::Algorithm::ChaCha20Poly1305,
            ProtonAlgorithm::AES_MAC_128_128 => coset::iana::Algorithm::AES_MAC_128_128,
            ProtonAlgorithm::AES_MAC_256_128 => coset::iana::Algorithm::AES_MAC_256_128,
            ProtonAlgorithm::AES_CCM_16_128_128 => coset::iana::Algorithm::AES_CCM_16_128_128,
            ProtonAlgorithm::AES_CCM_16_128_256 => coset::iana::Algorithm::AES_CCM_16_128_256,
            ProtonAlgorithm::AES_CCM_64_128_128 => coset::iana::Algorithm::AES_CCM_64_128_128,
            ProtonAlgorithm::AES_CCM_64_128_256 => coset::iana::Algorithm::AES_CCM_64_128_256,
            ProtonAlgorithm::IV_GENERATION => coset::iana::Algorithm::IV_GENERATION,
        }
    }
}

impl From<ProtonKeyOperation> for KeyOperation {
    fn from(value: ProtonKeyOperation) -> Self {
        match value {
            ProtonKeyOperation::Sign => KeyOperation::Sign,
            ProtonKeyOperation::Verify => KeyOperation::Verify,
            ProtonKeyOperation::Encrypt => KeyOperation::Encrypt,
            ProtonKeyOperation::Decrypt => KeyOperation::Decrypt,
            ProtonKeyOperation::WrapKey => KeyOperation::WrapKey,
            ProtonKeyOperation::UnwrapKey => KeyOperation::UnwrapKey,
            ProtonKeyOperation::DeriveKey => KeyOperation::DeriveKey,
            ProtonKeyOperation::DeriveBits => KeyOperation::DeriveBits,
            ProtonKeyOperation::MacCreate => KeyOperation::MacCreate,
            ProtonKeyOperation::MacVerify => KeyOperation::MacVerify,
        }
    }
}

impl From<ProtonRegisteredLabelKeyOperation> for RegisteredLabel<KeyOperation> {
    fn from(value: ProtonRegisteredLabelKeyOperation) -> Self {
        match value {
            ProtonRegisteredLabelKeyOperation::Assigned(t) => RegisteredLabel::Assigned(KeyOperation::from(t)),
            ProtonRegisteredLabelKeyOperation::Text(t) => RegisteredLabel::Text(t),
        }
    }
}

impl From<ProtonLabel> for Label {
    fn from(value: ProtonLabel) -> Self {
        match value {
            ProtonLabel::Int(t) => Label::Int(t),
            ProtonLabel::Text(t) => Label::Text(t),
        }
    }
}

impl From<ProtonValue> for Value {
    fn from(value: ProtonValue) -> Self {
        match value {
            ProtonValue::Integer(t) => Value::Integer(Integer::from(t)),
            ProtonValue::Bytes(t) => Value::Bytes(t),
            ProtonValue::Float(t) => Value::Float(t),
            ProtonValue::Text(t) => Value::Text(t),
            ProtonValue::Bool(t) => Value::Bool(t),
            ProtonValue::Null => Value::Null,
            ProtonValue::Tag(t, b) => {
                let cloned_value = b.deref().clone();
                let boxed = Box::new(Value::from(cloned_value));
                Value::Tag(t, boxed)
            }
            ProtonValue::Array(t) => Value::Array(t.into_iter().map(Value::from).collect()),
            ProtonValue::Map(t) => {
                let mut mapped: Vec<(Value, Value)> = vec![];
                for (v1, v2) in t {
                    mapped.push((Value::from(v1), Value::from(v2)));
                }
                Value::Map(mapped)
            }
        }
    }
}

impl From<ProtonInteger> for Integer {
    fn from(value: ProtonInteger) -> Self {
        let as_i128: i128 = i128::from(value);
        Integer::try_from(as_i128).unwrap_or_else(|_| Integer::from(0))
    }
}

impl From<ProtonRegisteredLabelWithPrivateAlgorithm> for coset::Algorithm {
    fn from(value: ProtonRegisteredLabelWithPrivateAlgorithm) -> Self {
        match value {
            ProtonRegisteredLabelWithPrivateAlgorithm::PrivateUse(t) => RegisteredLabelWithPrivate::PrivateUse(t),
            ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(t) => {
                RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::from(t))
            }
            ProtonRegisteredLabelWithPrivateAlgorithm::Text(t) => RegisteredLabelWithPrivate::Text(t),
        }
    }
}

impl From<ProtonPassCredentialExtensions> for CredentialExtensions {
    fn from(value: ProtonPassCredentialExtensions) -> Self {
        CredentialExtensions {
            hmac_secret: value.hmac_secret.map(StoredHmacSecret::from),
        }
    }
}

impl From<ProtonPassStoredHmacSecret> for StoredHmacSecret {
    fn from(value: ProtonPassStoredHmacSecret) -> Self {
        Self {
            cred_with_uv: value.cred_with_uv,
            cred_without_uv: value.cred_without_uv,
        }
    }
}
