use super::fetcher::WebauthnFetcher;
use super::protonpasskey::{
    ProtonAlgorithm, ProtonKey, ProtonKeyType, ProtonLabel, ProtonRegisteredLabelKeyType,
    ProtonRegisteredLabelWithPrivateAlgorithm, ProtonValue,
};
use super::{PasskeyError, PasskeyResult, ProtonPassKey};
use coset::CoseKey;
use coset::iana::Algorithm;
use passkey::authenticator::{Authenticator, UserValidationMethod};
use passkey::client::Client;
use passkey::crypto::rust_crypto::RustCryptoBackend;
use passkey_authenticator::extensions::HmacSecretConfig;
use passkey_authenticator::{UiHint, UserCheck};
use passkey_types::ctap2::Ctap2Error;
use passkey_types::{Passkey, ctap2::Aaguid};
use url::{ParseError, Url};

// AAGUID: 50726f74-6f6e-5061-7373-50726f746f6e
const AAGUID: [u8; 16] = [
    0x50, 0x72, 0x6F, 0x74, 0x6F, 0x6E, 0x50, 0x61, 0x73, 0x73, // ProtonPass
    0x50, 0x72, 0x6F, 0x74, 0x6F, 0x6E, // ProtonAG
];

const CONTENT_FORMAT_VERSION: u8 = 1;

const REGISTRATION_ALGORITHMS: &[Algorithm] = &[
    Algorithm::ES256,
    Algorithm::ESP256,
    Algorithm::EdDSA,
    Algorithm::Ed25519,
    Algorithm::ML_DSA_44,
    Algorithm::ML_DSA_65,
    Algorithm::ML_DSA_87,
];

const AKP_PUB_LABEL: i64 = -1;
const AKP_PRIV_LABEL: i64 = -2;
const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1312;
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;

pub(crate) struct MyUserValidationMethod {}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SerializedPassKey {
    #[serde(rename = "c")]
    pub content: Vec<u8>,
    #[serde(rename = "v")]
    pub format_version: u8,
}

#[async_trait::async_trait]
impl UserValidationMethod for MyUserValidationMethod {
    type PasskeyItem = Passkey;

    async fn check_user<'a>(
        &self,
        _credential: UiHint<'a, Self::PasskeyItem>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence: true,
            verification: true,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

pub(crate) fn get_client(
    pk: Option<ProtonPassKey>,
    fetcher: WebauthnFetcher,
    allows_insecure_localhost: bool,
) -> Client<Option<Passkey>, MyUserValidationMethod, RustCryptoBackend, public_suffix::PublicSuffixList, WebauthnFetcher>
{
    let mut authenticator = get_authenticator(pk);
    let _ = authenticator.set_algorithms(REGISTRATION_ALGORITHMS);
    Client::new_with_custom_tld_provider(authenticator, public_suffix::DEFAULT_PROVIDER, Some(fetcher))
        .allows_insecure_localhost(allows_insecure_localhost)
}

/// Checks that a freshly generated COSE key survives conversion to `ProtonKey` before it is saved.
/// Fails registration if the converted key has a `Reserved` kty or alg (an unknown type that the
/// serializer could not map), or if converting back does not give the original key. This avoids
/// storing a passkey that could never be used to log in.
pub(crate) fn ensure_storable(original: &CoseKey, converted: &ProtonKey) -> PasskeyResult<()> {
    let reserved_kty = matches!(
        converted.kty,
        ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::Reserved)
    );
    let reserved_alg = matches!(
        converted.alg,
        Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(
            ProtonAlgorithm::Reserved
        ))
    );
    if reserved_kty || reserved_alg || &CoseKey::from(converted.clone()) != original {
        return Err(PasskeyError::GenerationError(format!(
            "generated passkey with kty {:?} and alg {:?} cannot be stored",
            original.kty, original.alg
        )));
    }
    Ok(())
}

/// Returns the byte string stored under the integer `label` in the COSE key params, if any.
fn find_param_bytes(params: &[(ProtonLabel, ProtonValue)], label: i64) -> Option<&Vec<u8>> {
    params.iter().find_map(|(l, v)| match (l, v) {
        (ProtonLabel::Int(i), ProtonValue::Bytes(b)) if *i == label => Some(b),
        _ => None,
    })
}

/// Infers the ML-DSA variant from the length of the public key (label -1, fixed by FIPS 204).
/// Requires a private key (label -2) to be present. Returns `None` if the size is not recognised.
fn ml_dsa_algorithm_for_public_key(params: &[(ProtonLabel, ProtonValue)]) -> Option<ProtonAlgorithm> {
    find_param_bytes(params, AKP_PRIV_LABEL)?;
    match find_param_bytes(params, AKP_PUB_LABEL)?.len() {
        ML_DSA_44_PUBLIC_KEY_LEN => Some(ProtonAlgorithm::ML_DSA_44),
        ML_DSA_65_PUBLIC_KEY_LEN => Some(ProtonAlgorithm::ML_DSA_65),
        ML_DSA_87_PUBLIC_KEY_LEN => Some(ProtonAlgorithm::ML_DSA_87),
        _ => None,
    }
}

/// Fixes passkeys saved by older versions that stored `Reserved` for the key type or algorithm.
/// Only the labels were lost, the key material is intact, so they are inferred from it:
/// - `Reserved` kty with an ML-DSA private key and a public key of a known size becomes `AKP` with the matching ML-DSA algorithm.
/// - `AKP` with a `Reserved` alg gets the ML-DSA algorithm inferred from the public key size.
/// - `EC2` with a `Reserved` alg becomes `ES256` and `OKP` with a `Reserved` alg becomes `EdDSA`
///   (same signature format as ESP256 and Ed25519).
///
/// Anything else is left untouched.
pub(crate) fn repair_key(key: &mut ProtonKey) {
    let is_reserved_alg = matches!(
        key.alg,
        Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(
            ProtonAlgorithm::Reserved
        ))
    );
    let kty = match &key.kty {
        ProtonRegisteredLabelKeyType::Assigned(kty) => kty.clone(),
        ProtonRegisteredLabelKeyType::Text(_) => return,
    };

    let repaired_alg = match kty {
        ProtonKeyType::Reserved => match ml_dsa_algorithm_for_public_key(&key.params) {
            Some(alg) => {
                key.kty = ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::AKP);
                Some(alg)
            }
            None => None,
        },
        ProtonKeyType::AKP if is_reserved_alg => ml_dsa_algorithm_for_public_key(&key.params),
        ProtonKeyType::EC2 if is_reserved_alg => Some(ProtonAlgorithm::ES256),
        ProtonKeyType::OKP if is_reserved_alg => Some(ProtonAlgorithm::EdDSA),
        _ => None,
    };

    if let Some(alg) = repaired_alg {
        key.alg = Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(alg));
    }
}

pub(crate) fn get_authenticator(
    pk: Option<ProtonPassKey>,
) -> Authenticator<Option<Passkey>, MyUserValidationMethod, RustCryptoBackend> {
    let my_aaguid = Aaguid::from(AAGUID);
    let user_validation_method = MyUserValidationMethod {};

    let store: Option<Passkey> = pk.map(Passkey::from);
    Authenticator::new(my_aaguid, store, user_validation_method, RustCryptoBackend)
        .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential())
}

pub(crate) fn serialize_passkey(pk: &ProtonPassKey) -> PasskeyResult<Vec<u8>> {
    let serialized_contents = rmp_serde::to_vec_named(pk)
        .map_err(|e| PasskeyError::SerializationError(format!("Error serializing ProtonPassKey: {e:?}")))?;
    let serialized = SerializedPassKey {
        content: serialized_contents,
        format_version: CONTENT_FORMAT_VERSION,
    };

    rmp_serde::to_vec_named(&serialized)
        .map_err(|e| PasskeyError::SerializationError(format!("Error serializing SerializedPassKey: {e:?}")))
}

pub(crate) fn deserialize_passkey(content: &[u8]) -> PasskeyResult<ProtonPassKey> {
    let deserialized: SerializedPassKey = rmp_serde::from_slice(content)
        .map_err(|e| PasskeyError::SerializationError(format!("Error deserializing SerializedPassKey: {e:?}")))?;
    match deserialized.format_version {
        1 => {
            let mut key: ProtonPassKey = rmp_serde::from_slice(&deserialized.content)
                .map_err(|e| PasskeyError::SerializationError(format!("Error deserializing ProtonPassKey: {e:?}")))?;
            repair_key(&mut key.key);
            Ok(key)
        }
        _ => Err(PasskeyError::SerializationError(format!(
            "Unknown SerializedPassKey format_version {}",
            deserialized.format_version
        ))),
    }
}

pub(crate) fn parse_url(url: &str) -> PasskeyResult<Url> {
    match Url::parse(url) {
        Ok(url) => Ok(url),
        Err(err) => {
            if let ParseError::RelativeUrlWithoutBase = err {
                let with_protocol = format!("https://{url}");
                Ok(Url::parse(&with_protocol)
                    .map_err(|e| PasskeyError::InvalidUri(format!("Error parsing uri: {e:?}")))?)
            } else {
                Err(PasskeyError::InvalidUri(format!("Error parsing uri: {err:?}")))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::passkey::protonpasskey::{
        ProtonKey, ProtonKeyType, ProtonLabel, ProtonPassCredentialExtensions, ProtonPassStoredHmacSecret,
        ProtonRegisteredLabelKeyOperation, ProtonRegisteredLabelKeyType, ProtonValue,
    };

    use crate::passkey::protonpasskey::ProtonInteger;

    fn reserved_key(kty: ProtonKeyType, params: Vec<(ProtonLabel, ProtonValue)>) -> ProtonKey {
        ProtonKey {
            kty: ProtonRegisteredLabelKeyType::Assigned(kty),
            key_id: vec![],
            alg: Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(
                ProtonAlgorithm::Reserved,
            )),
            key_ops: vec![],
            base_iv: vec![],
            params,
        }
    }

    fn akp_params(pub_len: usize) -> Vec<(ProtonLabel, ProtonValue)> {
        vec![
            (ProtonLabel::Int(-1), ProtonValue::Bytes(vec![1; pub_len])),
            (ProtonLabel::Int(-2), ProtonValue::Bytes(vec![2; 32])),
        ]
    }

    fn assigned_alg(key: &ProtonKey) -> Option<ProtonAlgorithm> {
        match &key.alg {
            Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(a)) => Some(a.clone()),
            _ => None,
        }
    }

    #[test]
    fn repairs_reserved_ml_dsa_keys() {
        for (len, expected) in [
            (1312, ProtonAlgorithm::ML_DSA_44),
            (1952, ProtonAlgorithm::ML_DSA_65),
            (2592, ProtonAlgorithm::ML_DSA_87),
        ] {
            let mut key = reserved_key(ProtonKeyType::Reserved, akp_params(len));
            repair_key(&mut key);
            assert_eq!(key.kty, ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::AKP));
            assert_eq!(assigned_alg(&key), Some(expected));
        }
    }

    #[test]
    fn repairs_reserved_alg_for_ec2_and_okp() {
        let mut ec2 = reserved_key(ProtonKeyType::EC2, vec![]);
        repair_key(&mut ec2);
        assert_eq!(assigned_alg(&ec2), Some(ProtonAlgorithm::ES256));

        let mut okp = reserved_key(ProtonKeyType::OKP, vec![]);
        repair_key(&mut okp);
        assert_eq!(assigned_alg(&okp), Some(ProtonAlgorithm::EdDSA));
    }

    #[test]
    fn does_not_repair_unrecognised_keys() {
        let mut key = reserved_key(ProtonKeyType::Reserved, akp_params(10));
        let before = key.clone();
        repair_key(&mut key);
        assert_eq!(key, before);
    }

    #[test]
    fn deserialize_repairs_saved_reserved_passkey() {
        let mut pk = get_sample_passkey_v1();
        pk.key = reserved_key(ProtonKeyType::Reserved, akp_params(1312));
        let repaired = deserialize_passkey(&serialize_passkey(&pk).unwrap()).unwrap();
        assert_eq!(assigned_alg(&repaired.key), Some(ProtonAlgorithm::ML_DSA_44));
        let cose = CoseKey::from(repaired.key);
        assert_eq!(cose.alg, Some(coset::Algorithm::Assigned(Algorithm::ML_DSA_44)));
    }

    #[test]
    fn repaired_legacy_ml_dsa_passkey_can_sign() {
        use passkey::crypto::{CryptoBackend, PublicKeyT, SecretKeyT};

        for alg in [Algorithm::ML_DSA_44, Algorithm::ML_DSA_65, Algorithm::ML_DSA_87] {
            let backend = RustCryptoBackend;
            let original = backend.generate_key(alg).unwrap();

            let mut legacy = get_sample_passkey_v1();
            legacy.key = ProtonKey::from(original.to_cose_key());
            legacy.key.kty = ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::Reserved);
            legacy.key.alg = Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(
                ProtonAlgorithm::Reserved,
            ));

            let loaded = deserialize_passkey(&serialize_passkey(&legacy).unwrap()).unwrap();
            let mut repaired =
                <RustCryptoBackend as CryptoBackend>::SecretKey::from_cose_key(&CoseKey::from(loaded.key)).unwrap();

            let signature = repaired.sign(b"challenge");
            original.public_key().verify(b"challenge", &signature).unwrap();
        }
    }

    #[test]
    fn ml_dsa_cose_key_survives_conversion() {
        let cose = CoseKey {
            kty: coset::KeyType::Assigned(coset::iana::KeyType::AKP),
            alg: Some(coset::Algorithm::Assigned(Algorithm::ML_DSA_65)),
            params: vec![(coset::Label::Int(-2), coset::cbor::Value::Bytes(vec![2; 32]))],
            ..Default::default()
        };
        let converted = ProtonKey::from(cose.clone());
        assert!(ensure_storable(&cose, &converted).is_ok());
        assert_eq!(CoseKey::from(converted), cose);
    }

    #[test]
    fn ensure_storable_rejects_reserved() {
        let cose = CoseKey::default();
        let converted = reserved_key(ProtonKeyType::Reserved, vec![]);
        assert!(ensure_storable(&cose, &converted).is_err());
    }

    fn get_sample_passkey_v1() -> ProtonPassKey {
        ProtonPassKey {
            key: ProtonKey {
                kty: ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::EC2),
                key_id: vec![1, 2, 3],
                alg: None,
                key_ops: vec![ProtonRegisteredLabelKeyOperation::Text("some".to_string())],
                base_iv: vec![1, 2, 3],
                params: vec![
                    (
                        ProtonLabel::Text("label".to_string()),
                        ProtonValue::Integer(ProtonInteger::from(123456i128)),
                    ),
                    (
                        ProtonLabel::Int(123456789i64),
                        ProtonValue::Array(vec![
                            ProtonValue::Text("a value".to_string()),
                            ProtonValue::Bytes(vec![0x01, 0x02, 0x03]),
                        ]),
                    ),
                    (
                        ProtonLabel::Text("value is tag".to_string()),
                        ProtonValue::Tag(54u64, Box::new(ProtonValue::Bool(true))),
                    ),
                    (
                        ProtonLabel::Text("value is map".to_string()),
                        ProtonValue::Map(vec![
                            (ProtonValue::Float(1.234f64), ProtonValue::Bool(false)),
                            (ProtonValue::Integer(ProtonInteger::from(987i128)), ProtonValue::Null),
                        ]),
                    ),
                ],
            },
            credential_id: vec![1, 2, 3, 4, 5],
            rp_id: "some_rp_id".to_string(),
            user_handle: None,
            counter: None,
            extensions: ProtonPassCredentialExtensions::default(),
            username: None,
            user_display_name: None,
        }
    }

    fn get_sample_passkey_v2() -> ProtonPassKey {
        ProtonPassKey {
            key: ProtonKey {
                kty: ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::EC2),
                key_id: vec![1, 2, 3],
                alg: None,
                key_ops: vec![ProtonRegisteredLabelKeyOperation::Text("some".to_string())],
                base_iv: vec![1, 2, 3],
                params: vec![
                    (
                        ProtonLabel::Text("label".to_string()),
                        ProtonValue::Integer(ProtonInteger::from(123456i128)),
                    ),
                    (
                        ProtonLabel::Int(123456789i64),
                        ProtonValue::Array(vec![
                            ProtonValue::Text("a value".to_string()),
                            ProtonValue::Bytes(vec![0x01, 0x02, 0x03]),
                        ]),
                    ),
                    (
                        ProtonLabel::Text("value is tag".to_string()),
                        ProtonValue::Tag(54u64, Box::new(ProtonValue::Bool(true))),
                    ),
                    (
                        ProtonLabel::Text("value is map".to_string()),
                        ProtonValue::Map(vec![
                            (ProtonValue::Float(1.234f64), ProtonValue::Bool(false)),
                            (ProtonValue::Integer(ProtonInteger::from(987i128)), ProtonValue::Null),
                        ]),
                    ),
                ],
            },
            credential_id: vec![1, 2, 3, 4, 5],
            rp_id: "some_rp_id".to_string(),
            user_handle: None,
            counter: None,
            extensions: ProtonPassCredentialExtensions {
                hmac_secret: Some(ProtonPassStoredHmacSecret {
                    cred_with_uv: vec![0x01, 0x02, 0x03, 0x04],
                    cred_without_uv: Some(vec![0x05, 0x06, 0x07, 0x08]),
                }),
            },
            username: None,
            user_display_name: None,
        }
    }

    fn get_sample_passkey_v3() -> ProtonPassKey {
        ProtonPassKey {
            key: ProtonKey {
                kty: ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::EC2),
                key_id: vec![1, 2, 3],
                alg: None,
                key_ops: vec![ProtonRegisteredLabelKeyOperation::Text("some".to_string())],
                base_iv: vec![1, 2, 3],
                params: vec![
                    (
                        ProtonLabel::Text("label".to_string()),
                        ProtonValue::Integer(ProtonInteger::from(123456i128)),
                    ),
                    (
                        ProtonLabel::Int(123456789i64),
                        ProtonValue::Array(vec![
                            ProtonValue::Text("a value".to_string()),
                            ProtonValue::Bytes(vec![0x01, 0x02, 0x03]),
                        ]),
                    ),
                    (
                        ProtonLabel::Text("value is tag".to_string()),
                        ProtonValue::Tag(54u64, Box::new(ProtonValue::Bool(true))),
                    ),
                    (
                        ProtonLabel::Text("value is map".to_string()),
                        ProtonValue::Map(vec![
                            (ProtonValue::Float(1.234f64), ProtonValue::Bool(false)),
                            (ProtonValue::Integer(ProtonInteger::from(987i128)), ProtonValue::Null),
                        ]),
                    ),
                ],
            },
            credential_id: vec![1, 2, 3, 4, 5],
            rp_id: "some_rp_id".to_string(),
            user_handle: None,
            counter: None,
            extensions: ProtonPassCredentialExtensions {
                hmac_secret: Some(ProtonPassStoredHmacSecret {
                    cred_with_uv: vec![0x01, 0x02, 0x03, 0x04],
                    cred_without_uv: Some(vec![0x05, 0x06, 0x07, 0x08]),
                }),
            },
            username: Some("username".to_string()),
            user_display_name: Some("user_display_name".to_string()),
        }
    }

    #[test]
    fn can_serialize_and_deserialize_v1() {
        let passkey = get_sample_passkey_v1();
        let serialized = serialize_passkey(&passkey).expect("should be able to serialize passkey");
        let deserialized = deserialize_passkey(&serialized).expect("should be able to deserialize");
        assert_eq!(passkey, deserialized);
    }

    const SERIALIZED_V1: [u8; 506] = [
        130, 161, 99, 220, 1, 117, 204, 133, 204, 163, 107, 101, 121, 204, 134, 204, 163, 107, 116, 121, 204, 130, 204,
        161, 116, 204, 166, 97, 115, 115, 105, 103, 110, 204, 161, 99, 204, 163, 69, 67, 50, 204, 163, 107, 105, 100,
        204, 147, 1, 2, 3, 204, 163, 97, 108, 103, 204, 192, 204, 164, 107, 111, 112, 115, 204, 145, 204, 130, 204,
        161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 164, 115, 111, 109, 101, 204, 163, 98, 105, 118, 204,
        147, 1, 2, 3, 204, 163, 112, 97, 114, 204, 148, 204, 146, 204, 130, 204, 161, 116, 204, 163, 116, 120, 116,
        204, 161, 99, 204, 165, 108, 97, 98, 101, 108, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99,
        204, 129, 204, 165, 105, 110, 110, 101, 114, 204, 220, 0, 16, 64, 204, 204, 204, 226, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 204, 146, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99, 204, 206, 7, 91,
        204, 205, 21, 204, 130, 204, 161, 116, 204, 165, 97, 114, 114, 97, 121, 204, 161, 99, 204, 146, 204, 130, 204,
        161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 167, 97, 32, 118, 97, 108, 117, 101, 204, 130, 204, 161,
        116, 204, 165, 98, 121, 116, 101, 115, 204, 161, 99, 204, 147, 1, 2, 3, 204, 146, 204, 130, 204, 161, 116, 204,
        163, 116, 120, 116, 204, 161, 99, 204, 172, 118, 97, 108, 117, 101, 32, 105, 115, 32, 116, 97, 103, 204, 130,
        204, 161, 116, 204, 163, 116, 97, 103, 204, 161, 99, 204, 146, 54, 204, 130, 204, 161, 116, 204, 164, 98, 111,
        111, 108, 204, 161, 99, 204, 195, 204, 146, 204, 130, 204, 161, 116, 204, 163, 116, 120, 116, 204, 161, 99,
        204, 172, 118, 97, 108, 117, 101, 32, 105, 115, 32, 109, 97, 112, 204, 130, 204, 161, 116, 204, 163, 109, 97,
        112, 204, 161, 99, 204, 146, 204, 146, 204, 130, 204, 161, 116, 204, 165, 102, 108, 111, 97, 116, 204, 161, 99,
        204, 203, 63, 204, 243, 204, 190, 118, 204, 200, 204, 180, 57, 88, 204, 130, 204, 161, 116, 204, 164, 98, 111,
        111, 108, 204, 161, 99, 204, 194, 204, 146, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99,
        204, 129, 204, 165, 105, 110, 110, 101, 114, 204, 220, 0, 16, 204, 204, 204, 219, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 204, 129, 204, 161, 116, 204, 164, 110, 117, 108, 108, 204, 163, 99, 105, 100, 204, 149, 1, 2,
        3, 4, 5, 204, 163, 114, 105, 100, 204, 170, 115, 111, 109, 101, 95, 114, 112, 95, 105, 100, 204, 163, 117, 104,
        100, 204, 192, 204, 163, 99, 110, 116, 204, 192, 161, 118, 1,
    ];

    const SERIALIZED_V2: [u8; 571] = [
        130, 161, 99, 220, 1, 174, 204, 134, 204, 163, 107, 101, 121, 204, 134, 204, 163, 107, 116, 121, 204, 130, 204,
        161, 116, 204, 166, 97, 115, 115, 105, 103, 110, 204, 161, 99, 204, 163, 69, 67, 50, 204, 163, 107, 105, 100,
        204, 147, 1, 2, 3, 204, 163, 97, 108, 103, 204, 192, 204, 164, 107, 111, 112, 115, 204, 145, 204, 130, 204,
        161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 164, 115, 111, 109, 101, 204, 163, 98, 105, 118, 204,
        147, 1, 2, 3, 204, 163, 112, 97, 114, 204, 148, 204, 146, 204, 130, 204, 161, 116, 204, 163, 116, 120, 116,
        204, 161, 99, 204, 165, 108, 97, 98, 101, 108, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99,
        204, 129, 204, 165, 105, 110, 110, 101, 114, 204, 220, 0, 16, 64, 204, 204, 204, 226, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 204, 146, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99, 204, 206, 7, 91,
        204, 205, 21, 204, 130, 204, 161, 116, 204, 165, 97, 114, 114, 97, 121, 204, 161, 99, 204, 146, 204, 130, 204,
        161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 167, 97, 32, 118, 97, 108, 117, 101, 204, 130, 204, 161,
        116, 204, 165, 98, 121, 116, 101, 115, 204, 161, 99, 204, 147, 1, 2, 3, 204, 146, 204, 130, 204, 161, 116, 204,
        163, 116, 120, 116, 204, 161, 99, 204, 172, 118, 97, 108, 117, 101, 32, 105, 115, 32, 116, 97, 103, 204, 130,
        204, 161, 116, 204, 163, 116, 97, 103, 204, 161, 99, 204, 146, 54, 204, 130, 204, 161, 116, 204, 164, 98, 111,
        111, 108, 204, 161, 99, 204, 195, 204, 146, 204, 130, 204, 161, 116, 204, 163, 116, 120, 116, 204, 161, 99,
        204, 172, 118, 97, 108, 117, 101, 32, 105, 115, 32, 109, 97, 112, 204, 130, 204, 161, 116, 204, 163, 109, 97,
        112, 204, 161, 99, 204, 146, 204, 146, 204, 130, 204, 161, 116, 204, 165, 102, 108, 111, 97, 116, 204, 161, 99,
        204, 203, 63, 204, 243, 204, 190, 118, 204, 200, 204, 180, 57, 88, 204, 130, 204, 161, 116, 204, 164, 98, 111,
        111, 108, 204, 161, 99, 204, 194, 204, 146, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99,
        204, 129, 204, 165, 105, 110, 110, 101, 114, 204, 220, 0, 16, 204, 204, 204, 219, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 204, 129, 204, 161, 116, 204, 164, 110, 117, 108, 108, 204, 163, 99, 105, 100, 204, 149, 1, 2,
        3, 4, 5, 204, 163, 114, 105, 100, 204, 170, 115, 111, 109, 101, 95, 114, 112, 95, 105, 100, 204, 163, 117, 104,
        100, 204, 192, 204, 163, 99, 110, 116, 204, 192, 204, 163, 101, 120, 116, 204, 129, 204, 171, 104, 109, 97, 99,
        95, 115, 101, 99, 114, 101, 116, 204, 130, 204, 172, 99, 114, 101, 100, 95, 119, 105, 116, 104, 95, 117, 118,
        204, 148, 1, 2, 3, 4, 204, 175, 99, 114, 101, 100, 95, 119, 105, 116, 104, 111, 117, 116, 95, 117, 118, 204,
        148, 5, 6, 7, 8, 161, 118, 1,
    ];

    const SERIALIZED_V3: [u8; 609] = [
        130, 161, 99, 220, 1, 208, 204, 136, 204, 163, 107, 101, 121, 204, 134, 204, 163, 107, 116, 121, 204, 130, 204,
        161, 116, 204, 166, 97, 115, 115, 105, 103, 110, 204, 161, 99, 204, 163, 69, 67, 50, 204, 163, 107, 105, 100,
        204, 147, 1, 2, 3, 204, 163, 97, 108, 103, 204, 192, 204, 164, 107, 111, 112, 115, 204, 145, 204, 130, 204,
        161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 164, 115, 111, 109, 101, 204, 163, 98, 105, 118, 204,
        147, 1, 2, 3, 204, 163, 112, 97, 114, 204, 148, 204, 146, 204, 130, 204, 161, 116, 204, 163, 116, 120, 116,
        204, 161, 99, 204, 165, 108, 97, 98, 101, 108, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99,
        204, 129, 204, 165, 105, 110, 110, 101, 114, 204, 220, 0, 16, 64, 204, 204, 204, 226, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 204, 146, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99, 204, 206, 7, 91,
        204, 205, 21, 204, 130, 204, 161, 116, 204, 165, 97, 114, 114, 97, 121, 204, 161, 99, 204, 146, 204, 130, 204,
        161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 167, 97, 32, 118, 97, 108, 117, 101, 204, 130, 204, 161,
        116, 204, 165, 98, 121, 116, 101, 115, 204, 161, 99, 204, 147, 1, 2, 3, 204, 146, 204, 130, 204, 161, 116, 204,
        163, 116, 120, 116, 204, 161, 99, 204, 172, 118, 97, 108, 117, 101, 32, 105, 115, 32, 116, 97, 103, 204, 130,
        204, 161, 116, 204, 163, 116, 97, 103, 204, 161, 99, 204, 146, 54, 204, 130, 204, 161, 116, 204, 164, 98, 111,
        111, 108, 204, 161, 99, 204, 195, 204, 146, 204, 130, 204, 161, 116, 204, 163, 116, 120, 116, 204, 161, 99,
        204, 172, 118, 97, 108, 117, 101, 32, 105, 115, 32, 109, 97, 112, 204, 130, 204, 161, 116, 204, 163, 109, 97,
        112, 204, 161, 99, 204, 146, 204, 146, 204, 130, 204, 161, 116, 204, 165, 102, 108, 111, 97, 116, 204, 161, 99,
        204, 203, 63, 204, 243, 204, 190, 118, 204, 200, 204, 180, 57, 88, 204, 130, 204, 161, 116, 204, 164, 98, 111,
        111, 108, 204, 161, 99, 204, 194, 204, 146, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99,
        204, 129, 204, 165, 105, 110, 110, 101, 114, 204, 220, 0, 16, 204, 204, 204, 219, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 204, 129, 204, 161, 116, 204, 164, 110, 117, 108, 108, 204, 163, 99, 105, 100, 204, 149, 1, 2,
        3, 4, 5, 204, 163, 114, 105, 100, 204, 170, 115, 111, 109, 101, 95, 114, 112, 95, 105, 100, 204, 163, 117, 104,
        100, 204, 192, 204, 163, 99, 110, 116, 204, 192, 204, 163, 101, 120, 116, 204, 129, 204, 171, 104, 109, 97, 99,
        95, 115, 101, 99, 114, 101, 116, 204, 130, 204, 172, 99, 114, 101, 100, 95, 119, 105, 116, 104, 95, 117, 118,
        204, 148, 1, 2, 3, 4, 204, 175, 99, 114, 101, 100, 95, 119, 105, 116, 104, 111, 117, 116, 95, 117, 118, 204,
        148, 5, 6, 7, 8, 204, 163, 117, 100, 110, 204, 177, 117, 115, 101, 114, 95, 100, 105, 115, 112, 108, 97, 121,
        95, 110, 97, 109, 101, 204, 162, 117, 110, 204, 168, 117, 115, 101, 114, 110, 97, 109, 101, 161, 118, 1,
    ];

    #[test]
    fn deserialization_regression_test_v1() {
        let expected = get_sample_passkey_v1();

        let deserialized = deserialize_passkey(&SERIALIZED_V1).expect("should be able to deserialize");
        assert_eq!(expected, deserialized);
    }

    #[test]
    fn deserialize_v2_matches_all_v1_fields() {
        let expected = get_sample_passkey_v1();

        let deserialized_v2 = deserialize_passkey(&SERIALIZED_V2).expect("should be able to deserialize");

        assert_eq!(expected.key, deserialized_v2.key);
        assert_eq!(expected.credential_id, deserialized_v2.credential_id);
        assert_eq!(expected.rp_id, deserialized_v2.rp_id);
        assert_eq!(expected.user_handle, deserialized_v2.user_handle);
        assert_eq!(expected.counter, deserialized_v2.counter);
    }

    #[test]
    fn deserialization_regression_test_v2() {
        let expected = get_sample_passkey_v2();

        let deserialized = deserialize_passkey(&SERIALIZED_V2).expect("should be able to deserialize");
        assert_eq!(expected, deserialized);
    }

    #[test]
    fn deserialize_v3_matches_all_v2_fields() {
        let expected = get_sample_passkey_v2();

        let deserialized_v3 = deserialize_passkey(&SERIALIZED_V3).expect("should be able to deserialize");

        assert_eq!(expected.key, deserialized_v3.key);
        assert_eq!(expected.credential_id, deserialized_v3.credential_id);
        assert_eq!(expected.rp_id, deserialized_v3.rp_id);
        assert_eq!(expected.user_handle, deserialized_v3.user_handle);
        assert_eq!(expected.counter, deserialized_v3.counter);
    }

    #[test]
    fn serialization_regression_test_v3() {
        let expected = get_sample_passkey_v3();

        let serialized = serialize_passkey(&expected).expect("should be able to serialize");
        assert_eq!(SERIALIZED_V3.to_vec(), serialized);
    }
}
