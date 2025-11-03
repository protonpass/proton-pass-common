use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub enum WasmMarkdownOperation {
    Bold,
    Italic,
    Strikethrough,
    Header1,
    Header2,
    Header3,
    Header4,
    Header5,
    Header6,
    CreateOrderedList,
    CreateUnorderedList,
    IndentList,
    UnindentList,
    Blockquote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub enum WasmMarkdownSpanStyle {
    Bold,
    Italic,
    Strikethrough,
    Header1,
    Header2,
    Header3,
    Header4,
    Header5,
    Header6,
    Code,
    CodeBlock,
    Link,
    OrderedListItem,
    UnorderedListItem,
    Blockquote,
    MarkdownMarker,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WasmMarkdownStyledSpan {
    pub start: u32,
    pub end: u32,
    pub style: WasmMarkdownSpanStyle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}
