mod authentication_parser;
pub mod fetcher;
mod generate;
mod parser;
mod passkey_handling;
mod protonpasskey;
mod protonpasskeydeserializer;
mod protonpasskeyserializer;
mod resolve;
mod utils;

pub use fetcher::{FetchError, WebauthnClientFetcher, WebauthnDomainsResponse, WebauthnFetcher};
pub use generate::{
    CreatePasskeyData, CreatePasskeyIosRequest, CreatePasskeyResponse, generate_passkey_for_domain,
    generate_passkey_for_ios, parse_create_passkey_data,
};
pub use protonpasskey::ProtonPassKey;
pub use resolve::{
    AuthenticateWithPasskeyAndroidRequest, AuthenticateWithPasskeyIosRequest, AuthenticateWithPasskeyIosResponse,
    ResolveChallengeResponse, resolve_challenge_for_android, resolve_challenge_for_domain, resolve_challenge_for_ios,
};

pub type PasskeyResult<T> = Result<T, PasskeyError>;

#[derive(Clone, Debug, proton_pass_derive::Error)]
pub enum PasskeyError {
    InvalidUri(String),
    RuntimeError(String),
    GenerationError(String),
    ResolveChallengeError(String),
    SerializationError(String),
}
