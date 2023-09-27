pub use proton_pass_common::alias_prefix::AliasPrefixError;

pub struct AliasPrefixValidator;

impl AliasPrefixValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self, prefix: String) -> Result<(), AliasPrefixError> {
        proton_pass_common::alias_prefix::validate_alias_prefix(&prefix)
    }
}
