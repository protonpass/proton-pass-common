use super::{PasskeyError, PasskeyResult, ProtonPassKey};
use passkey::authenticator::{Authenticator, UserValidationMethod};
use passkey_authenticator::UserCheck;
use passkey_types::ctap2::Ctap2Error;
use passkey_types::{ctap2::Aaguid, Passkey};
use url::{ParseError, Url};

// AAGUID: 50726f74-6f6e-5061-7373-50726f746f6e
const AAGUID: [u8; 16] = [
    0x50, 0x72, 0x6F, 0x74, 0x6F, 0x6E, 0x50, 0x61, 0x73, 0x73, // ProtonPass
    0x50, 0x72, 0x6F, 0x74, 0x6F, 0x6E, // ProtonAG
];

const CONTENT_FORMAT_VERSION: u8 = 1;

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
        _credential: Option<&'a Self::PasskeyItem>,
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

pub(crate) fn get_authenticator(pk: Option<ProtonPassKey>) -> Authenticator<Option<Passkey>, MyUserValidationMethod> {
    let my_aaguid = Aaguid::from(AAGUID);
    let user_validation_method = MyUserValidationMethod {};

    let store: Option<Passkey> = pk.map(Passkey::from);
    let mut authenticator = Authenticator::new(my_aaguid, store, user_validation_method);
    authenticator.set_display_name("Proton Pass".to_string());
    authenticator
}

pub(crate) fn serialize_passkey(pk: &ProtonPassKey) -> PasskeyResult<Vec<u8>> {
    let serialized_contents = rmp_serde::to_vec_named(pk)
        .map_err(|e| PasskeyError::SerializationError(format!("Error serializing ProtonPassKey: {:?}", e)))?;
    let serialized = SerializedPassKey {
        content: serialized_contents,
        format_version: CONTENT_FORMAT_VERSION,
    };

    rmp_serde::to_vec_named(&serialized)
        .map_err(|e| PasskeyError::SerializationError(format!("Error serializing SerializedPassKey: {:?}", e)))
}

pub(crate) fn deserialize_passkey(content: &[u8]) -> PasskeyResult<ProtonPassKey> {
    let deserialized: SerializedPassKey = rmp_serde::from_slice(content)
        .map_err(|e| PasskeyError::SerializationError(format!("Error deserializing SerializedPassKey: {:?}", e)))?;
    match deserialized.format_version {
        1 => rmp_serde::from_slice(&deserialized.content)
            .map_err(|e| PasskeyError::SerializationError(format!("Error deserializing ProtonPassKey: {:?}", e))),
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
                let with_protocol = format!("https://{}", url);
                Ok(Url::parse(&with_protocol)
                    .map_err(|e| PasskeyError::InvalidUri(format!("Error parsing uri: {:?}", e)))?)
            } else {
                Err(PasskeyError::InvalidUri(format!("Error parsing uri: {:?}", err)))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::passkey::protonpasskey::{
        ProtonInteger, ProtonKey, ProtonKeyType, ProtonLabel, ProtonPassCredentialExtensions,
        ProtonPassStoredHmacSecret, ProtonRegisteredLabelKeyOperation, ProtonRegisteredLabelKeyType, ProtonValue,
    };

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

    #[test]
    fn deserialization_regression_test_v1() {
        let expected = get_sample_passkey_v1();

        let deserialized = deserialize_passkey(&SERIALIZED_V1).expect("should be able to deserialize");
        assert_eq!(expected, deserialized);
    }

    #[test]
    fn serialization_regression_test_v2() {
        let expected = get_sample_passkey_v2();

        let serialized = serialize_passkey(&expected).expect("should be able to serialize");
        assert_eq!(SERIALIZED_V2.to_vec(), serialized);
    }

    #[test]
    fn deserialization_regression_test_v2() {
        let expected = get_sample_passkey_v2();

        let deserialized = deserialize_passkey(&SERIALIZED_V2).expect("should be able to deserialize");
        assert_eq!(expected, deserialized);
    }
}
