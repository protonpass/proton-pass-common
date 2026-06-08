#[derive(Clone, Debug, Hash, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct VaultId(pub(crate) String);

impl VaultId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}
