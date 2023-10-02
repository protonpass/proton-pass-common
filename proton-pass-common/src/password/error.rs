use proton_pass_derive::Error;

#[derive(Debug, Error)]
pub enum PasswordGeneratorError {
    FailToGenerate(String),
}
