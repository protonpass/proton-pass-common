use super::protonpasskey::{
    ProtonAlgorithm, ProtonInteger, ProtonKey, ProtonKeyOperation, ProtonKeyType, ProtonLabel,
    ProtonPassCredentialExtensions, ProtonPassKey, ProtonPassStoredHmacSecret, ProtonRegisteredLabelKeyOperation,
    ProtonRegisteredLabelKeyType, ProtonRegisteredLabelWithPrivateAlgorithm, ProtonValue,
};
use coset::cbor::value::Integer;
use coset::cbor::Value;
use coset::iana::KeyOperation;
use coset::{CoseKey, KeyType, Label, RegisteredLabel, RegisteredLabelWithPrivate};
use passkey::types::Passkey;
use passkey_types::{CredentialExtensions, StoredHmacSecret};
use std::ops::Deref;

impl From<Passkey> for ProtonPassKey {
    fn from(value: Passkey) -> Self {
        ProtonPassKey {
            key: value.key.into(),
            credential_id: value.credential_id.to_vec(),
            rp_id: value.rp_id,
            user_handle: value.user_handle.map(|v| v.to_vec()),
            counter: value.counter,
            extensions: ProtonPassCredentialExtensions::from(value.extensions),
        }
    }
}

impl From<CoseKey> for ProtonKey {
    fn from(value: CoseKey) -> Self {
        let mut key_ops = Vec::new();
        for op in value.key_ops {
            key_ops.push(ProtonRegisteredLabelKeyOperation::from(op));
        }

        let mut params: Vec<(ProtonLabel, ProtonValue)> = Vec::new();
        for (label, value) in value.params {
            params.push((ProtonLabel::from(label), ProtonValue::from(value)));
        }

        ProtonKey {
            kty: ProtonRegisteredLabelKeyType::from(value.kty),
            key_id: value.key_id,
            alg: value.alg.map(ProtonRegisteredLabelWithPrivateAlgorithm::from),
            key_ops,
            base_iv: value.base_iv,
            params,
        }
    }
}

impl From<KeyType> for ProtonRegisteredLabelKeyType {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Assigned(t) => ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::from(t)),
            KeyType::Text(t) => ProtonRegisteredLabelKeyType::Text(t),
        }
    }
}

impl From<coset::iana::KeyType> for ProtonKeyType {
    fn from(value: coset::iana::KeyType) -> Self {
        match value {
            coset::iana::KeyType::Reserved => ProtonKeyType::Reserved,
            coset::iana::KeyType::OKP => ProtonKeyType::OKP,
            coset::iana::KeyType::EC2 => ProtonKeyType::EC2,
            coset::iana::KeyType::RSA => ProtonKeyType::RSA,
            coset::iana::KeyType::Symmetric => ProtonKeyType::Symmetric,
            coset::iana::KeyType::HSS_LMS => ProtonKeyType::HSS_LMS,
            coset::iana::KeyType::WalnutDSA => ProtonKeyType::WalnutDSA,

            _ => ProtonKeyType::Reserved,
        }
    }
}

impl From<coset::iana::Algorithm> for ProtonAlgorithm {
    fn from(value: coset::iana::Algorithm) -> Self {
        match value {
            coset::iana::Algorithm::RS1 => ProtonAlgorithm::RS1,
            coset::iana::Algorithm::WalnutDSA => ProtonAlgorithm::WalnutDSA,
            coset::iana::Algorithm::RS512 => ProtonAlgorithm::RS512,
            coset::iana::Algorithm::RS384 => ProtonAlgorithm::RS384,
            coset::iana::Algorithm::RS256 => ProtonAlgorithm::RS256,
            coset::iana::Algorithm::ES256K => ProtonAlgorithm::ES256K,
            coset::iana::Algorithm::HSS_LMS => ProtonAlgorithm::HSS_LMS,
            coset::iana::Algorithm::SHAKE256 => ProtonAlgorithm::SHAKE256,
            coset::iana::Algorithm::SHA_512 => ProtonAlgorithm::SHA_512,
            coset::iana::Algorithm::SHA_384 => ProtonAlgorithm::SHA_384,
            coset::iana::Algorithm::RSAES_OAEP_SHA_512 => ProtonAlgorithm::RSAES_OAEP_SHA_512,
            coset::iana::Algorithm::RSAES_OAEP_SHA_256 => ProtonAlgorithm::RSAES_OAEP_SHA_256,
            coset::iana::Algorithm::RSAES_OAEP_RFC_8017_default => ProtonAlgorithm::RSAES_OAEP_RFC_8017_default,
            coset::iana::Algorithm::PS512 => ProtonAlgorithm::PS512,
            coset::iana::Algorithm::PS384 => ProtonAlgorithm::PS384,
            coset::iana::Algorithm::PS256 => ProtonAlgorithm::PS256,
            coset::iana::Algorithm::ES512 => ProtonAlgorithm::ES512,
            coset::iana::Algorithm::ES384 => ProtonAlgorithm::ES384,
            coset::iana::Algorithm::ECDH_SS_A256KW => ProtonAlgorithm::ECDH_SS_A256KW,
            coset::iana::Algorithm::ECDH_SS_A192KW => ProtonAlgorithm::ECDH_SS_A192KW,
            coset::iana::Algorithm::ECDH_SS_A128KW => ProtonAlgorithm::ECDH_SS_A128KW,
            coset::iana::Algorithm::ECDH_ES_A256KW => ProtonAlgorithm::ECDH_ES_A256KW,
            coset::iana::Algorithm::ECDH_ES_A192KW => ProtonAlgorithm::ECDH_ES_A192KW,
            coset::iana::Algorithm::ECDH_ES_A128KW => ProtonAlgorithm::ECDH_ES_A128KW,
            coset::iana::Algorithm::ECDH_SS_HKDF_512 => ProtonAlgorithm::ECDH_SS_HKDF_512,
            coset::iana::Algorithm::ECDH_SS_HKDF_256 => ProtonAlgorithm::ECDH_SS_HKDF_256,
            coset::iana::Algorithm::ECDH_ES_HKDF_512 => ProtonAlgorithm::ECDH_ES_HKDF_512,
            coset::iana::Algorithm::ECDH_ES_HKDF_256 => ProtonAlgorithm::ECDH_ES_HKDF_256,
            coset::iana::Algorithm::SHAKE128 => ProtonAlgorithm::SHAKE128,
            coset::iana::Algorithm::SHA_512_256 => ProtonAlgorithm::SHA_512_256,
            coset::iana::Algorithm::SHA_256 => ProtonAlgorithm::SHA_256,
            coset::iana::Algorithm::SHA_256_64 => ProtonAlgorithm::SHA_256_64,
            coset::iana::Algorithm::SHA_1 => ProtonAlgorithm::SHA_1,
            coset::iana::Algorithm::Direct_HKDF_AES_256 => ProtonAlgorithm::Direct_HKDF_AES_256,
            coset::iana::Algorithm::Direct_HKDF_AES_128 => ProtonAlgorithm::Direct_HKDF_AES_128,
            coset::iana::Algorithm::Direct_HKDF_SHA_512 => ProtonAlgorithm::Direct_HKDF_SHA_512,
            coset::iana::Algorithm::Direct_HKDF_SHA_256 => ProtonAlgorithm::Direct_HKDF_SHA_256,
            coset::iana::Algorithm::EdDSA => ProtonAlgorithm::EdDSA,
            coset::iana::Algorithm::ES256 => ProtonAlgorithm::ES256,
            coset::iana::Algorithm::Direct => ProtonAlgorithm::Direct,
            coset::iana::Algorithm::A256KW => ProtonAlgorithm::A256KW,
            coset::iana::Algorithm::A192KW => ProtonAlgorithm::A192KW,
            coset::iana::Algorithm::A128KW => ProtonAlgorithm::A128KW,
            coset::iana::Algorithm::Reserved => ProtonAlgorithm::Reserved,
            coset::iana::Algorithm::A128GCM => ProtonAlgorithm::A128GCM,
            coset::iana::Algorithm::A192GCM => ProtonAlgorithm::A192GCM,
            coset::iana::Algorithm::A256GCM => ProtonAlgorithm::A256GCM,
            coset::iana::Algorithm::HMAC_256_64 => ProtonAlgorithm::HMAC_256_64,
            coset::iana::Algorithm::HMAC_256_256 => ProtonAlgorithm::HMAC_256_256,
            coset::iana::Algorithm::HMAC_384_384 => ProtonAlgorithm::HMAC_384_384,
            coset::iana::Algorithm::HMAC_512_512 => ProtonAlgorithm::HMAC_512_512,
            coset::iana::Algorithm::AES_CCM_16_64_128 => ProtonAlgorithm::AES_CCM_16_64_128,
            coset::iana::Algorithm::AES_CCM_16_64_256 => ProtonAlgorithm::AES_CCM_16_64_256,
            coset::iana::Algorithm::AES_CCM_64_64_128 => ProtonAlgorithm::AES_CCM_64_64_128,
            coset::iana::Algorithm::AES_CCM_64_64_256 => ProtonAlgorithm::AES_CCM_64_64_256,
            coset::iana::Algorithm::AES_MAC_128_64 => ProtonAlgorithm::AES_MAC_128_64,
            coset::iana::Algorithm::AES_MAC_256_64 => ProtonAlgorithm::AES_MAC_256_64,
            coset::iana::Algorithm::ChaCha20Poly1305 => ProtonAlgorithm::ChaCha20Poly1305,
            coset::iana::Algorithm::AES_MAC_128_128 => ProtonAlgorithm::AES_MAC_128_128,
            coset::iana::Algorithm::AES_MAC_256_128 => ProtonAlgorithm::AES_MAC_256_128,
            coset::iana::Algorithm::AES_CCM_16_128_128 => ProtonAlgorithm::AES_CCM_16_128_128,
            coset::iana::Algorithm::AES_CCM_16_128_256 => ProtonAlgorithm::AES_CCM_16_128_256,
            coset::iana::Algorithm::AES_CCM_64_128_128 => ProtonAlgorithm::AES_CCM_64_128_128,
            coset::iana::Algorithm::AES_CCM_64_128_256 => ProtonAlgorithm::AES_CCM_64_128_256,
            coset::iana::Algorithm::IV_GENERATION => ProtonAlgorithm::IV_GENERATION,

            _ => ProtonAlgorithm::Reserved,
        }
    }
}

impl From<KeyOperation> for ProtonKeyOperation {
    fn from(value: KeyOperation) -> Self {
        match value {
            KeyOperation::Sign => ProtonKeyOperation::Sign,
            KeyOperation::Verify => ProtonKeyOperation::Verify,
            KeyOperation::Encrypt => ProtonKeyOperation::Encrypt,
            KeyOperation::Decrypt => ProtonKeyOperation::Decrypt,
            KeyOperation::WrapKey => ProtonKeyOperation::WrapKey,
            KeyOperation::UnwrapKey => ProtonKeyOperation::UnwrapKey,
            KeyOperation::DeriveKey => ProtonKeyOperation::DeriveKey,
            KeyOperation::DeriveBits => ProtonKeyOperation::DeriveBits,
            KeyOperation::MacCreate => ProtonKeyOperation::MacCreate,
            KeyOperation::MacVerify => ProtonKeyOperation::MacVerify,

            _ => ProtonKeyOperation::Sign,
        }
    }
}

impl From<RegisteredLabel<KeyOperation>> for ProtonRegisteredLabelKeyOperation {
    fn from(value: RegisteredLabel<KeyOperation>) -> Self {
        match value {
            RegisteredLabel::Assigned(t) => ProtonRegisteredLabelKeyOperation::Assigned(ProtonKeyOperation::from(t)),
            RegisteredLabel::Text(t) => ProtonRegisteredLabelKeyOperation::Text(t),
        }
    }
}

impl From<Label> for ProtonLabel {
    fn from(value: Label) -> Self {
        match value {
            Label::Int(t) => ProtonLabel::Int(t),
            Label::Text(t) => ProtonLabel::Text(t),
        }
    }
}

impl From<Box<Value>> for ProtonValue {
    fn from(value: Box<Value>) -> Self {
        let unboxed = value.deref().clone();
        ProtonValue::from(unboxed)
    }
}

impl From<Value> for ProtonValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Integer(t) => ProtonValue::Integer(ProtonInteger::from(t)),
            Value::Bytes(t) => ProtonValue::Bytes(t),
            Value::Float(t) => ProtonValue::Float(t),
            Value::Text(t) => ProtonValue::Text(t),
            Value::Bool(t) => ProtonValue::Bool(t),
            Value::Null => ProtonValue::Null,
            Value::Tag(t, b) => {
                let boxed = Box::new(ProtonValue::from(b));
                ProtonValue::Tag(t, boxed)
            }
            Value::Array(t) => ProtonValue::Array(t.into_iter().map(ProtonValue::from).collect()),
            Value::Map(t) => {
                let mut mapped: Vec<(ProtonValue, ProtonValue)> = vec![];
                for (v1, v2) in t {
                    mapped.push((ProtonValue::from(v1), ProtonValue::from(v2)));
                }
                ProtonValue::Map(mapped)
            }

            _ => ProtonValue::Integer(ProtonInteger::from(0i128)),
        }
    }
}

impl From<Integer> for ProtonInteger {
    fn from(value: Integer) -> Self {
        ProtonInteger::from(i128::from(value))
    }
}

impl From<coset::Algorithm> for ProtonRegisteredLabelWithPrivateAlgorithm {
    fn from(value: coset::Algorithm) -> Self {
        match value {
            RegisteredLabelWithPrivate::PrivateUse(t) => ProtonRegisteredLabelWithPrivateAlgorithm::PrivateUse(t),
            RegisteredLabelWithPrivate::Assigned(t) => {
                ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(ProtonAlgorithm::from(t))
            }
            RegisteredLabelWithPrivate::Text(t) => ProtonRegisteredLabelWithPrivateAlgorithm::Text(t),
        }
    }
}

impl From<CredentialExtensions> for ProtonPassCredentialExtensions {
    fn from(value: CredentialExtensions) -> Self {
        ProtonPassCredentialExtensions {
            hmac_secret: value
                .hmac_secret
                .as_ref()
                .map(|secret| ProtonPassStoredHmacSecret::from(secret.clone())),
        }
    }
}

impl From<StoredHmacSecret> for ProtonPassStoredHmacSecret {
    fn from(value: StoredHmacSecret) -> Self {
        Self {
            cred_without_uv: value.cred_without_uv.clone(),
            cred_with_uv: value.cred_with_uv.clone(),
        }
    }
}
