#[derive(Clone, Debug, Hash, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct FolderId(pub(crate) String);

impl FolderId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}
