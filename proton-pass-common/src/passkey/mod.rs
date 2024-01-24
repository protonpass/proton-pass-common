mod passkey_handling;
mod protonpasskey;
mod protonpasskeydeserializer;
mod protonpasskeyserializer;

pub use passkey_handling::{generate_passkey_for_domain, resolve_challenge_for_domain, CreatePassKeyResponse};
pub use protonpasskey::ProtonPassKey;

pub type PasskeyResult<T> = Result<T, PasskeyError>;

#[derive(Clone, Debug, proton_pass_derive::Error)]
pub enum PasskeyError {
    InvalidUri(String),
    RuntimeError(String),
    GenerationError(String),
    ResolveChallengeError(String),
    SerializationError(String),
}
