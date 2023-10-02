pub use proton_pass_common::password::error::PasswordGeneratorError;
pub use proton_pass_common::password::random_generator::RandomPasswordConfig;

pub struct RandomPasswordGenerator;

impl RandomPasswordGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(&self, config: RandomPasswordConfig) -> Result<String, PasswordGeneratorError> {
        config.generate()
    }
}
