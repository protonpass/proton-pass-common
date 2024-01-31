use super::{PasskeyError, PasskeyResult, ProtonPassKey};
use passkey::authenticator::{Authenticator, UserValidationMethod};
use passkey_types::{ctap2::Aaguid, Passkey};

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
    async fn check_user_verification(&self) -> bool {
        true
    }

    async fn check_user_presence(&self) -> bool {
        true
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

pub(crate) fn get_authenticator(pk: Option<ProtonPassKey>) -> Authenticator<Option<Passkey>, MyUserValidationMethod> {
    let my_aaguid = Aaguid::new_empty();
    let user_validation_method = MyUserValidationMethod {};

    let store: Option<Passkey> = pk.map(Passkey::from);
    Authenticator::new(my_aaguid, store, user_validation_method)
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::passkey::protonpasskey::{
        ProtonInteger, ProtonKey, ProtonKeyType, ProtonLabel, ProtonRegisteredLabelKeyOperation,
        ProtonRegisteredLabelKeyType, ProtonValue,
    };

    fn get_sample_passkey() -> ProtonPassKey {
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
        }
    }

    #[test]
    fn can_serialize_and_deserialize() {
        let passkey = get_sample_passkey();
        let serialized = serialize_passkey(&passkey).expect("should be able to serialize passkey");
        println!("{:?}", serialized);
        let deserialized = deserialize_passkey(&serialized).expect("should be able to deserialize");
        assert_eq!(passkey, deserialized);
    }

    #[test]
    fn serialization_regression_test() {
        let input = [
            130, 161, 99, 220, 1, 117, 204, 133, 204, 163, 107, 101, 121, 204, 134, 204, 163, 107, 116, 121, 204, 130,
            204, 161, 116, 204, 166, 97, 115, 115, 105, 103, 110, 204, 161, 99, 204, 163, 69, 67, 50, 204, 163, 107,
            105, 100, 204, 147, 1, 2, 3, 204, 163, 97, 108, 103, 204, 192, 204, 164, 107, 111, 112, 115, 204, 145, 204,
            130, 204, 161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 164, 115, 111, 109, 101, 204, 163, 98, 105,
            118, 204, 147, 1, 2, 3, 204, 163, 112, 97, 114, 204, 148, 204, 146, 204, 130, 204, 161, 116, 204, 163, 116,
            120, 116, 204, 161, 99, 204, 165, 108, 97, 98, 101, 108, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116,
            204, 161, 99, 204, 129, 204, 165, 105, 110, 110, 101, 114, 204, 220, 0, 16, 64, 204, 204, 204, 226, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 204, 146, 204, 130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161,
            99, 204, 206, 7, 91, 204, 205, 21, 204, 130, 204, 161, 116, 204, 165, 97, 114, 114, 97, 121, 204, 161, 99,
            204, 146, 204, 130, 204, 161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 167, 97, 32, 118, 97, 108,
            117, 101, 204, 130, 204, 161, 116, 204, 165, 98, 121, 116, 101, 115, 204, 161, 99, 204, 147, 1, 2, 3, 204,
            146, 204, 130, 204, 161, 116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 172, 118, 97, 108, 117, 101, 32,
            105, 115, 32, 116, 97, 103, 204, 130, 204, 161, 116, 204, 163, 116, 97, 103, 204, 161, 99, 204, 146, 54,
            204, 130, 204, 161, 116, 204, 164, 98, 111, 111, 108, 204, 161, 99, 204, 195, 204, 146, 204, 130, 204, 161,
            116, 204, 163, 116, 120, 116, 204, 161, 99, 204, 172, 118, 97, 108, 117, 101, 32, 105, 115, 32, 109, 97,
            112, 204, 130, 204, 161, 116, 204, 163, 109, 97, 112, 204, 161, 99, 204, 146, 204, 146, 204, 130, 204, 161,
            116, 204, 165, 102, 108, 111, 97, 116, 204, 161, 99, 204, 203, 63, 204, 243, 204, 190, 118, 204, 200, 204,
            180, 57, 88, 204, 130, 204, 161, 116, 204, 164, 98, 111, 111, 108, 204, 161, 99, 204, 194, 204, 146, 204,
            130, 204, 161, 116, 204, 163, 105, 110, 116, 204, 161, 99, 204, 129, 204, 165, 105, 110, 110, 101, 114,
            204, 220, 0, 16, 204, 204, 204, 219, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 204, 129, 204, 161, 116,
            204, 164, 110, 117, 108, 108, 204, 163, 99, 105, 100, 204, 149, 1, 2, 3, 4, 5, 204, 163, 114, 105, 100,
            204, 170, 115, 111, 109, 101, 95, 114, 112, 95, 105, 100, 204, 163, 117, 104, 100, 204, 192, 204, 163, 99,
            110, 116, 204, 192, 161, 118, 1,
        ];
        let expected = get_sample_passkey();

        let serialized = serialize_passkey(&expected).expect("should be able to serialize");
        assert_eq!(input.to_vec(), serialized);

        let deserialized = deserialize_passkey(&input).expect("should be able to deserialize");
        assert_eq!(expected, deserialized);
    }
}
