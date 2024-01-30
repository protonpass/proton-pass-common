use super::{PasskeyError, PasskeyResult, ProtonPassKey};
use passkey::authenticator::{Authenticator, UserValidationMethod};
use passkey_types::{ctap2::Aaguid, Passkey};

const CONTENT_FORMAT_VERSION: u8 = 1;

pub(crate) struct MyUserValidationMethod {}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SerializedPassKey {
    pub content: Vec<u8>,
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
        ProtonKey, ProtonLabel, ProtonRegisteredLabelKeyOperation, ProtonRegisteredLabelKeyType, ProtonValue,
    };

    #[test]
    fn can_serialize_and_deserialize() {
        let passkey = ProtonPassKey {
            key: ProtonKey {
                kty: ProtonRegisteredLabelKeyType::Text("test".to_string()),
                key_id: vec![1, 2, 3],
                alg: None,
                key_ops: vec![ProtonRegisteredLabelKeyOperation::Text("some".to_string())],
                base_iv: vec![1, 2, 3],
                params: vec![(
                    ProtonLabel::Text("label".to_string()),
                    ProtonValue::Text("value".to_string()),
                )],
            },
            credential_id: vec![1, 2, 3, 4, 5],
            rp_id: "some_rp_id".to_string(),
            user_handle: None,
            counter: None,
        };
        let serialized = serialize_passkey(&passkey).expect("should be able to serialize passkey");
        let deserialized = deserialize_passkey(&serialized).expect("should be able to deserialize");
        assert_eq!(passkey, deserialized);
    }
}
