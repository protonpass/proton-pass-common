#![allow(clippy::upper_case_acronyms, non_camel_case_types)]

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProtonPassKey {
    #[serde(rename = "key")]
    pub key: ProtonKey,
    #[serde(rename = "cid")]
    pub credential_id: Vec<u8>,
    #[serde(rename = "rid")]
    pub rp_id: String,
    #[serde(rename = "uhd")]
    pub user_handle: Option<Vec<u8>>,
    #[serde(rename = "cnt")]
    pub counter: Option<u32>,
    #[serde(rename = "ext")]
    #[serde(default)]
    pub extensions: ProtonPassCredentialExtensions,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProtonKey {
    #[serde(rename = "kty")]
    pub kty: ProtonRegisteredLabelKeyType,
    #[serde(rename = "kid")]
    pub key_id: Vec<u8>,
    #[serde(rename = "alg")]
    pub alg: Option<ProtonRegisteredLabelWithPrivateAlgorithm>,
    #[serde(rename = "kops")]
    pub key_ops: Vec<ProtonRegisteredLabelKeyOperation>,
    #[serde(rename = "biv")]
    pub base_iv: Vec<u8>,
    #[serde(rename = "par")]
    pub params: Vec<(ProtonLabel, ProtonValue)>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum ProtonKeyType {
    Reserved = 0,
    OKP = 1,
    EC2 = 2,
    RSA = 3,
    Symmetric = 4,
    HSS_LMS = 5,
    WalnutDSA = 6,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "t", content = "c")]
pub enum ProtonRegisteredLabelKeyType {
    #[serde(rename = "assign")]
    Assigned(ProtonKeyType),
    #[serde(rename = "txt")]
    Text(String),
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "t", content = "c")]
pub enum ProtonRegisteredLabelKeyOperation {
    #[serde(rename = "assign")]
    Assigned(ProtonKeyOperation),
    #[serde(rename = "txt")]
    Text(String),
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "t", content = "c")]
pub enum ProtonRegisteredLabelWithPrivateAlgorithm {
    #[serde(rename = "priv")]
    PrivateUse(i64),
    #[serde(rename = "assign")]
    Assigned(ProtonAlgorithm),
    #[serde(rename = "txt")]
    Text(String),
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum ProtonAlgorithm {
    RS1 = -65535,
    WalnutDSA = -260,
    RS512 = -259,
    RS384 = -258,
    RS256 = -257,
    ES256K = -47,
    HSS_LMS = -46,
    SHAKE256 = -45,
    SHA_512 = -44,
    SHA_384 = -43,
    RSAES_OAEP_SHA_512 = -42,
    RSAES_OAEP_SHA_256 = -41,
    RSAES_OAEP_RFC_8017_default = -40,
    PS512 = -39,
    PS384 = -38,
    PS256 = -37,
    ES512 = -36,
    ES384 = -35,
    ECDH_SS_A256KW = -34,
    ECDH_SS_A192KW = -33,
    ECDH_SS_A128KW = -32,
    ECDH_ES_A256KW = -31,
    ECDH_ES_A192KW = -30,
    ECDH_ES_A128KW = -29,
    ECDH_SS_HKDF_512 = -28,
    ECDH_SS_HKDF_256 = -27,
    ECDH_ES_HKDF_512 = -26,
    ECDH_ES_HKDF_256 = -25,
    SHAKE128 = -18,
    SHA_512_256 = -17,
    SHA_256 = -16,
    SHA_256_64 = -15,
    SHA_1 = -14,
    Direct_HKDF_AES_256 = -13,
    Direct_HKDF_AES_128 = -12,
    Direct_HKDF_SHA_512 = -11,
    Direct_HKDF_SHA_256 = -10,
    EdDSA = -8,
    ES256 = -7,
    Direct = -6,
    A256KW = -5,
    A192KW = -4,
    A128KW = -3,
    Reserved = 0,
    A128GCM = 1,
    A192GCM = 2,
    A256GCM = 3,
    HMAC_256_64 = 4,
    HMAC_256_256 = 5,
    HMAC_384_384 = 6,
    HMAC_512_512 = 7,
    AES_CCM_16_64_128 = 10,
    AES_CCM_16_64_256 = 11,
    AES_CCM_64_64_128 = 12,
    AES_CCM_64_64_256 = 13,
    AES_MAC_128_64 = 14,
    AES_MAC_256_64 = 15,
    ChaCha20Poly1305 = 24,
    AES_MAC_128_128 = 25,
    AES_MAC_256_128 = 26,
    AES_CCM_16_128_128 = 30,
    AES_CCM_16_128_256 = 31,
    AES_CCM_64_128_128 = 32,
    AES_CCM_64_128_256 = 33,
    IV_GENERATION = 34,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum ProtonKeyOperation {
    Sign = 1,
    Verify = 2,
    Encrypt = 3,
    Decrypt = 4,
    WrapKey = 5,
    UnwrapKey = 6,
    DeriveKey = 7,
    DeriveBits = 8,
    MacCreate = 9,
    MacVerify = 10,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "t", content = "c")]
pub enum ProtonLabel {
    #[serde(rename = "int")]
    Int(i64),
    #[serde(rename = "txt")]
    Text(String),
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "t", content = "c")]
pub enum ProtonValue {
    #[serde(rename = "int")]
    Integer(ProtonInteger),
    #[serde(rename = "bytes")]
    Bytes(Vec<u8>),
    #[serde(rename = "float")]
    Float(f64),
    #[serde(rename = "txt")]
    Text(String),
    #[serde(rename = "bool")]
    Bool(bool),
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "tag")]
    Tag(u64, Box<ProtonValue>),
    #[serde(rename = "array")]
    Array(Vec<ProtonValue>),
    #[serde(rename = "map")]
    Map(Vec<(ProtonValue, ProtonValue)>),
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProtonInteger {
    #[serde(rename = "inner")]
    inner: Vec<u8>,
}

impl From<i128> for ProtonInteger {
    fn from(value: i128) -> Self {
        Self {
            inner: value.to_le_bytes().to_vec(),
        }
    }
}

impl From<ProtonInteger> for i128 {
    fn from(value: ProtonInteger) -> Self {
        let mut as_bytes: [u8; 16] = [0; 16];
        for (idx, value) in value.inner.into_iter().enumerate() {
            as_bytes[idx] = value;
        }
        i128::from_le_bytes(as_bytes)
    }
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProtonPassCredentialExtensions {
    pub hmac_secret: Option<ProtonPassStoredHmacSecret>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProtonPassStoredHmacSecret {
    pub cred_with_uv: Vec<u8>,
    pub cred_without_uv: Option<Vec<u8>>,
}
