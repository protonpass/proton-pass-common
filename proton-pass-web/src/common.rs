use wasm_bindgen::prelude::*;

pub struct StringValue {
    pub(crate) value: String,
}

#[wasm_bindgen]
pub struct ExportedStringVec(pub(crate) Vec<StringValue>);

#[wasm_bindgen]
impl ExportedStringVec {
    pub fn get_name(&self, index: usize) -> String {
        self.0[index].value.clone()
    }
}
