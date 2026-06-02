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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WasmMarkdownSelection {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WasmMarkdownDocument {
    pub nodes: Vec<WasmMarkdownNode>,
    pub root: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WasmMarkdownNode {
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<u32>,
    pub children: Vec<u32>,
    pub kind: WasmMarkdownNodeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_link: Option<WasmMarkdownSafeLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsafe_link: Option<WasmMarkdownUnsafeLink>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub enum WasmMarkdownNodeKind {
    Paragraph,
    Heading,
    Text,
    Strong,
    Emphasis,
    Strikethrough,
    InlineCode,
    CodeBlock,
    Link,
    Blockquote,
    OrderedList,
    UnorderedList,
    ListItem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WasmMarkdownSafeLink {
    pub href: String,
    pub scheme: WasmMarkdownLinkScheme,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WasmMarkdownUnsafeLink {
    pub raw: String,
    pub reason: WasmMarkdownUnsafeLinkReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub enum WasmMarkdownLinkScheme {
    Http,
    Https,
    Mailto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub enum WasmMarkdownUnsafeLinkReason {
    Empty,
    UnsupportedScheme,
    ControlCharacter,
    UserInfo,
    RelativeOrFragment,
    Malformed,
}
