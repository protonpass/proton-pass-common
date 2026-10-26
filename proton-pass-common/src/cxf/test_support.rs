use proton_pass_types::Passkey as PassPasskey;

use crate::passkey::passkey_handling::serialize_passkey;
use crate::passkey::{
    ProtonAlgorithm, ProtonInteger, ProtonKey, ProtonKeyType, ProtonLabel, ProtonPassCredentialExtensions,
    ProtonPassKey, ProtonRegisteredLabelKeyType, ProtonRegisteredLabelWithPrivateAlgorithm, ProtonValue,
};
use coset::iana::{Ec2KeyParameter, EllipticCurve};

pub(crate) fn sample_passkey() -> PassPasskey {
    let rp_id = "example.com";
    let credential_id = vec![1, 2, 3, 4];
    let user_handle = vec![5, 6, 7, 8];

    let scalar: [u8; 32] = [
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    ];
    let secret = p256::SecretKey::from_slice(&scalar).expect("fixed scalar is a valid P-256 key");
    let public_point = p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&secret.public_key(), false);

    let proton_pass_key = ProtonPassKey {
        key: ProtonKey {
            kty: ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::EC2),
            key_id: Vec::new(),
            alg: Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(
                ProtonAlgorithm::ES256,
            )),
            key_ops: Vec::new(),
            base_iv: Vec::new(),
            params: vec![
                (
                    ProtonLabel::Int(Ec2KeyParameter::Crv as i64),
                    ProtonValue::Integer(ProtonInteger::from(EllipticCurve::P_256 as i128)),
                ),
                (
                    ProtonLabel::Int(Ec2KeyParameter::X as i64),
                    ProtonValue::Bytes(public_point.x().expect("P-256 public key has an x coordinate").to_vec()),
                ),
                (
                    ProtonLabel::Int(Ec2KeyParameter::Y as i64),
                    ProtonValue::Bytes(public_point.y().expect("P-256 public key has a y coordinate").to_vec()),
                ),
                (
                    ProtonLabel::Int(Ec2KeyParameter::D as i64),
                    ProtonValue::Bytes(scalar.to_vec()),
                ),
            ],
        },
        credential_id: credential_id.clone(),
        rp_id: rp_id.to_string(),
        user_handle: Some(user_handle.clone()),
        counter: Some(0),
        extensions: ProtonPassCredentialExtensions::default(),
        user_display_name: Some("Jane Doe".to_string()),
        username: Some("jane".to_string()),
    };

    PassPasskey {
        key_id: "key-01".to_string(),
        content: serialize_passkey(&proton_pass_key).expect("sample passkey serializes"),
        domain: rp_id.to_string(),
        rp_id: rp_id.to_string(),
        rp_name: "Example".to_string(),
        user_name: "jane".to_string(),
        user_display_name: "Jane Doe".to_string(),
        user_id: user_handle.clone(),
        create_time: 0,
        note: String::new(),
        credential_id,
        user_handle,
        creation_data: None,
    }
}
