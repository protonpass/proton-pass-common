mod cursor;
mod editor;
mod list_operations;
mod newline;
mod operations;
mod renderer;
mod undo;

#[cfg(test)]
mod tests;

pub use editor::MarkdownEditor;
pub use renderer::{render_markdown, SpanStyle, StyledSpan};

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
}

pub type Result<T> = std::result::Result<T, MarkdownError>;
