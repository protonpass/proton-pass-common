use proton_pass_common::domain::get_root_domain;
pub use proton_pass_common::domain::GetRootDomainError;

pub struct DomainManager;

impl DomainManager {
    pub fn new() -> Self {
        Self
    }

    pub fn get_root_domain(&self, input: String) -> Result<String, GetRootDomainError> {
        get_root_domain(&input)
    }
}
