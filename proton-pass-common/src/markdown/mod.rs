mod cursor;
mod document;
mod editor;
mod list_operations;
mod newline;
mod operations;
mod parser;
mod renderer;
mod undo;
mod utf16;

#[cfg(test)]
mod tests;

pub use document::{
    classify_markdown_link, MarkdownDocument, MarkdownLink, MarkdownLinkScheme, MarkdownNode, MarkdownNodeId,
    MarkdownNodeKind, MarkdownUnsafeLinkReason,
};
pub use editor::MarkdownEditor;
pub use parser::{parse_markdown_document, parse_markdown_document_with_limits, MarkdownParseLimits};
pub use renderer::{render_editor_spans, SpanStyle, StyledSpan};

use proton_pass_derive::Error;

/// Operations that can be applied to markdown text
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Bold,
    Italic,
    Strikethrough,
    Header(u8), // 1-6
    CreateOrderedList,
    CreateUnorderedList,
    IndentList,
    UnindentList,
    Blockquote,
}

/// Errors that can occur during markdown operations
#[derive(Debug, Error)]
pub enum MarkdownError {
    InvalidCursorPosition(String),
    InvalidSelection(String),
    InvalidHeaderLevel(String),
    InvalidOperation(String),
    ParsingError(String),
    DocumentTooLarge(String),
    TooDeep(String),
    TooManyNodes(String),
    PayloadTooLarge(String),
    InvalidLink(String),
}

pub type Result<T> = std::result::Result<T, MarkdownError>;
