use crate::password::error::PasswordGeneratorError;
use passwords::PasswordGenerator;

#[derive(Debug)]
pub struct RandomPasswordConfig {
    pub length: u32,
    pub numbers: bool,
    pub uppercase_letters: bool,
    pub symbols: bool,
}

impl RandomPasswordConfig {
    pub fn new(length: u32, numbers: bool, uppercase_letters: bool, symbols: bool) -> Self {
        Self {
            length,
            numbers,
            uppercase_letters,
            symbols,
        }
    }

    pub fn generate(&self) -> Result<String, PasswordGeneratorError> {
        match self.as_generator().generate_one() {
            Ok(value) => Ok(value),
            Err(error_message) => Err(PasswordGeneratorError::FailToGenerate(error_message.to_string())),
        }
    }

    fn as_generator(&self) -> PasswordGenerator {
        PasswordGenerator {
            length: self.length as usize,
            numbers: self.numbers,
            lowercase_letters: true,
            uppercase_letters: self.uppercase_letters,
            symbols: self.symbols,
            spaces: false,
            exclude_similar_characters: true,
            strict: false,
        }
    }
}
