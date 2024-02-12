mod generate;
mod passkey_handling;
mod protonpasskey;
mod protonpasskeydeserializer;
mod protonpasskeyserializer;
mod resolve;

pub use generate::{generate_passkey_for_domain, parse_create_passkey_data, CreatePassKeyResponse, CreatePasskeyData};
pub use protonpasskey::ProtonPassKey;
pub use resolve::{resolve_challenge_for_domain, ResolveChallengeResponse};

pub type PasskeyResult<T> = Result<T, PasskeyError>;

#[derive(Clone, Debug, proton_pass_derive::Error)]
pub enum PasskeyError {
    InvalidUri(String),
    RuntimeError(String),
    GenerationError(String),
    ResolveChallengeError(String),
    SerializationError(String),
}
