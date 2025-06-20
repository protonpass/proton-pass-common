pub use proton_pass_common::file::FileGroup;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum WasmFileGroup {
    Image,
    Photo,
    VectorImage,
    Video,
    Audio,
    Key,
    Text,
    Calendar,
    Pdf,
    Word,
    PowerPoint,
    Excel,
    Document,
    Unknown,
}

impl From<FileGroup> for WasmFileGroup {
    fn from(value: FileGroup) -> Self {
        match value {
            FileGroup::Image => WasmFileGroup::Image,
            FileGroup::Photo => WasmFileGroup::Photo,
            FileGroup::VectorImage => WasmFileGroup::VectorImage,
            FileGroup::Video => WasmFileGroup::Video,
            FileGroup::Audio => WasmFileGroup::Audio,
            FileGroup::Key => WasmFileGroup::Key,
            FileGroup::Text => WasmFileGroup::Text,
            FileGroup::Calendar => WasmFileGroup::Calendar,
            FileGroup::Pdf => WasmFileGroup::Pdf,
            FileGroup::Word => WasmFileGroup::Word,
            FileGroup::PowerPoint => WasmFileGroup::PowerPoint,
            FileGroup::Excel => WasmFileGroup::Excel,
            FileGroup::Document => WasmFileGroup::Document,
            FileGroup::Unknown => WasmFileGroup::Unknown,
        }
    }
}
