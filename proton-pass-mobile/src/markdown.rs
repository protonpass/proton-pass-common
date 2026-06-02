use proton_pass_common::markdown::{
    parse_markdown_document as common_parse_markdown_document, MarkdownDocument as CommonMarkdownDocument,
    MarkdownEditor as CommonMarkdownEditor, MarkdownError as CommonMarkdownError, MarkdownLink as CommonMarkdownLink,
    MarkdownLinkScheme as CommonMarkdownLinkScheme, MarkdownNode as CommonMarkdownNode,
    MarkdownNodeKind as CommonMarkdownNodeKind, MarkdownUnsafeLinkReason as CommonMarkdownUnsafeLinkReason,
    Operation as CommonOperation, SpanStyle as CommonSpanStyle, StyledSpan as CommonStyledSpan,
};
use std::sync::{Arc, Mutex, MutexGuard};

// START MAPPING TYPES

#[derive(Debug, proton_pass_derive::Error, uniffi::Error)]
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

impl From<CommonMarkdownError> for MarkdownError {
    fn from(e: CommonMarkdownError) -> Self {
        match e {
            CommonMarkdownError::InvalidCursorPosition(s) => MarkdownError::InvalidCursorPosition(s),
            CommonMarkdownError::InvalidSelection(s) => MarkdownError::InvalidSelection(s),
            CommonMarkdownError::InvalidHeaderLevel(s) => MarkdownError::InvalidHeaderLevel(s),
            CommonMarkdownError::InvalidOperation(s) => MarkdownError::InvalidOperation(s),
            CommonMarkdownError::ParsingError(s) => MarkdownError::ParsingError(s),
            CommonMarkdownError::DocumentTooLarge(s) => MarkdownError::DocumentTooLarge(s),
            CommonMarkdownError::TooDeep(s) => MarkdownError::TooDeep(s),
            CommonMarkdownError::TooManyNodes(s) => MarkdownError::TooManyNodes(s),
            CommonMarkdownError::PayloadTooLarge(s) => MarkdownError::PayloadTooLarge(s),
            CommonMarkdownError::InvalidLink(s) => MarkdownError::InvalidLink(s),
        }
    }
}

type Result<T> = std::result::Result<T, MarkdownError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownOperation {
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

impl From<MarkdownOperation> for CommonOperation {
    fn from(op: MarkdownOperation) -> Self {
        match op {
            MarkdownOperation::Bold => CommonOperation::Bold,
            MarkdownOperation::Italic => CommonOperation::Italic,
            MarkdownOperation::Strikethrough => CommonOperation::Strikethrough,
            MarkdownOperation::Header1 => CommonOperation::Header(1),
            MarkdownOperation::Header2 => CommonOperation::Header(2),
            MarkdownOperation::Header3 => CommonOperation::Header(3),
            MarkdownOperation::Header4 => CommonOperation::Header(4),
            MarkdownOperation::Header5 => CommonOperation::Header(5),
            MarkdownOperation::Blockquote => CommonOperation::Blockquote,
            MarkdownOperation::Header6 => CommonOperation::Header(6),
            MarkdownOperation::CreateOrderedList => CommonOperation::CreateOrderedList,
            MarkdownOperation::CreateUnorderedList => CommonOperation::CreateUnorderedList,
            MarkdownOperation::IndentList => CommonOperation::IndentList,
            MarkdownOperation::UnindentList => CommonOperation::UnindentList,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownSpanStyle {
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

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MarkdownStyledSpan {
    pub start: u32,
    pub end: u32,
    pub style: MarkdownSpanStyle,
    pub level: Option<u8>,
    pub number: Option<u32>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MarkdownSelection {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownNodeKind {
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

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownLinkScheme {
    Http,
    Https,
    Mailto,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MarkdownUnsafeLinkReason {
    Empty,
    UnsupportedScheme,
    ControlCharacter,
    UserInfo,
    RelativeOrFragment,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MarkdownSafeLink {
    pub href: String,
    pub scheme: MarkdownLinkScheme,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MarkdownUnsafeLink {
    pub raw: String,
    pub reason: MarkdownUnsafeLinkReason,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MarkdownNode {
    pub id: u32,
    pub parent_id: Option<u32>,
    pub children: Vec<u32>,
    pub kind: MarkdownNodeKind,
    pub text: Option<String>,
    pub level: Option<u8>,
    pub start_number: Option<u32>,
    pub language: Option<String>,
    pub title: Option<String>,
    pub safe_link: Option<MarkdownSafeLink>,
    pub unsafe_link: Option<MarkdownUnsafeLink>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MarkdownDocument {
    pub nodes: Vec<MarkdownNode>,
    pub root: Vec<u32>,
}

impl From<CommonStyledSpan> for MarkdownStyledSpan {
    fn from(span: CommonStyledSpan) -> Self {
        let (style, level, number, url) = match span.style {
            CommonSpanStyle::Bold => (MarkdownSpanStyle::Bold, None, None, None),
            CommonSpanStyle::Italic => (MarkdownSpanStyle::Italic, None, None, None),
            CommonSpanStyle::Strikethrough => (MarkdownSpanStyle::Strikethrough, None, None, None),
            CommonSpanStyle::Header(level) => {
                let style = match level {
                    1 => MarkdownSpanStyle::Header1,
                    2 => MarkdownSpanStyle::Header2,
                    3 => MarkdownSpanStyle::Header3,
                    4 => MarkdownSpanStyle::Header4,
                    5 => MarkdownSpanStyle::Header5,
                    6 => MarkdownSpanStyle::Header6,
                    _ => MarkdownSpanStyle::Header1,
                };
                (style, Some(level), None, None)
            }
            CommonSpanStyle::Code => (MarkdownSpanStyle::Code, None, None, None),
            CommonSpanStyle::CodeBlock => (MarkdownSpanStyle::CodeBlock, None, None, None),
            CommonSpanStyle::Link { url } => (MarkdownSpanStyle::Link, None, None, Some(url)),
            CommonSpanStyle::OrderedListItem { level, number } => {
                (MarkdownSpanStyle::OrderedListItem, Some(level), Some(number), None)
            }
            CommonSpanStyle::UnorderedListItem { level } => {
                (MarkdownSpanStyle::UnorderedListItem, Some(level), None, None)
            }
            CommonSpanStyle::Blockquote => (MarkdownSpanStyle::Blockquote, None, None, None),
            CommonSpanStyle::MarkdownMarker => (MarkdownSpanStyle::MarkdownMarker, None, None, None),
        };

        MarkdownStyledSpan {
            start: span.start,
            end: span.end,
            style,
            level,
            number,
            url,
        }
    }
}

impl From<CommonMarkdownDocument> for MarkdownDocument {
    fn from(document: CommonMarkdownDocument) -> Self {
        Self {
            nodes: document.nodes.into_iter().map(MarkdownNode::from).collect(),
            root: document.root.into_iter().map(|id| id.0).collect(),
        }
    }
}

impl From<CommonMarkdownNode> for MarkdownNode {
    fn from(node: CommonMarkdownNode) -> Self {
        let mut markdown_node = MarkdownNode {
            id: node.id.0,
            parent_id: node.parent.map(|id| id.0),
            children: node.children.into_iter().map(|id| id.0).collect(),
            kind: MarkdownNodeKind::Paragraph,
            text: None,
            level: None,
            start_number: None,
            language: None,
            title: None,
            safe_link: None,
            unsafe_link: None,
        };

        match node.kind {
            CommonMarkdownNodeKind::Paragraph => markdown_node.kind = MarkdownNodeKind::Paragraph,
            CommonMarkdownNodeKind::Heading { level } => {
                markdown_node.kind = MarkdownNodeKind::Heading;
                markdown_node.level = Some(level);
            }
            CommonMarkdownNodeKind::Text(text) => {
                markdown_node.kind = MarkdownNodeKind::Text;
                markdown_node.text = Some(text);
            }
            CommonMarkdownNodeKind::Strong => markdown_node.kind = MarkdownNodeKind::Strong,
            CommonMarkdownNodeKind::Emphasis => markdown_node.kind = MarkdownNodeKind::Emphasis,
            CommonMarkdownNodeKind::Strikethrough => markdown_node.kind = MarkdownNodeKind::Strikethrough,
            CommonMarkdownNodeKind::InlineCode(code) => {
                markdown_node.kind = MarkdownNodeKind::InlineCode;
                markdown_node.text = Some(code);
            }
            CommonMarkdownNodeKind::CodeBlock { language, code } => {
                markdown_node.kind = MarkdownNodeKind::CodeBlock;
                markdown_node.language = language;
                markdown_node.text = Some(code);
            }
            CommonMarkdownNodeKind::Link { destination, title } => {
                markdown_node.kind = MarkdownNodeKind::Link;
                markdown_node.title = title;
                match destination {
                    CommonMarkdownLink::Safe { href, scheme } => {
                        markdown_node.safe_link = Some(MarkdownSafeLink {
                            href,
                            scheme: MarkdownLinkScheme::from(scheme),
                        });
                    }
                    CommonMarkdownLink::Unsafe { raw, reason } => {
                        markdown_node.unsafe_link = Some(MarkdownUnsafeLink {
                            raw,
                            reason: MarkdownUnsafeLinkReason::from(reason),
                        });
                    }
                }
            }
            CommonMarkdownNodeKind::Blockquote => markdown_node.kind = MarkdownNodeKind::Blockquote,
            CommonMarkdownNodeKind::OrderedList { start } => {
                markdown_node.kind = MarkdownNodeKind::OrderedList;
                markdown_node.start_number = Some(start);
            }
            CommonMarkdownNodeKind::UnorderedList => markdown_node.kind = MarkdownNodeKind::UnorderedList,
            CommonMarkdownNodeKind::ListItem => markdown_node.kind = MarkdownNodeKind::ListItem,
        }

        markdown_node
    }
}

impl From<CommonMarkdownLinkScheme> for MarkdownLinkScheme {
    fn from(scheme: CommonMarkdownLinkScheme) -> Self {
        match scheme {
            CommonMarkdownLinkScheme::Http => MarkdownLinkScheme::Http,
            CommonMarkdownLinkScheme::Https => MarkdownLinkScheme::Https,
            CommonMarkdownLinkScheme::Mailto => MarkdownLinkScheme::Mailto,
        }
    }
}

impl From<CommonMarkdownUnsafeLinkReason> for MarkdownUnsafeLinkReason {
    fn from(reason: CommonMarkdownUnsafeLinkReason) -> Self {
        match reason {
            CommonMarkdownUnsafeLinkReason::Empty => MarkdownUnsafeLinkReason::Empty,
            CommonMarkdownUnsafeLinkReason::UnsupportedScheme => MarkdownUnsafeLinkReason::UnsupportedScheme,
            CommonMarkdownUnsafeLinkReason::ControlCharacter => MarkdownUnsafeLinkReason::ControlCharacter,
            CommonMarkdownUnsafeLinkReason::UserInfo => MarkdownUnsafeLinkReason::UserInfo,
            CommonMarkdownUnsafeLinkReason::RelativeOrFragment => MarkdownUnsafeLinkReason::RelativeOrFragment,
            CommonMarkdownUnsafeLinkReason::Malformed => MarkdownUnsafeLinkReason::Malformed,
        }
    }
}

#[uniffi::export]
pub fn parse_markdown_document(text: String) -> Result<MarkdownDocument> {
    Ok(MarkdownDocument::from(common_parse_markdown_document(&text)?))
}

// END MAPPING TYPES

#[derive(uniffi::Object)]
pub struct MarkdownEditor {
    editor: Arc<Mutex<CommonMarkdownEditor>>,
}

#[uniffi::export]
impl MarkdownEditor {
    #[uniffi::constructor]
    pub fn new(text: String) -> Self {
        Self {
            editor: Arc::new(Mutex::new(CommonMarkdownEditor::new(text))),
        }
    }

    pub fn get_text(&self) -> String {
        self.editor
            .lock()
            .map(|editor| editor.get_text().to_string())
            .unwrap_or_default()
    }

    pub fn get_cursor(&self) -> u32 {
        self.editor.lock().map(|editor| editor.get_cursor()).unwrap_or_default()
    }

    pub fn get_selection(&self) -> Option<MarkdownSelection> {
        self.editor.lock().ok().and_then(|editor| {
            editor
                .get_selection()
                .map(|(start, end)| MarkdownSelection { start, end })
        })
    }

    pub fn set_cursor(&self, position: u32) -> Result<()> {
        Ok(self.lock_editor()?.set_cursor(position)?)
    }

    pub fn set_selection(&self, start: u32, end: u32) -> Result<()> {
        Ok(self.lock_editor()?.set_selection(start, end)?)
    }

    pub fn apply_operation(&self, operation: MarkdownOperation) -> Result<()> {
        Ok(self.lock_editor()?.apply_operation(operation.into())?)
    }

    pub fn insert_newline(&self) -> Result<()> {
        Ok(self.lock_editor()?.insert_newline()?)
    }

    pub fn undo(&self) -> bool {
        self.editor.lock().map(|mut editor| editor.undo()).unwrap_or(false)
    }

    pub fn redo(&self) -> bool {
        self.editor.lock().map(|mut editor| editor.redo()).unwrap_or(false)
    }

    pub fn can_undo(&self) -> bool {
        self.editor.lock().map(|editor| editor.can_undo()).unwrap_or(false)
    }

    pub fn can_redo(&self) -> bool {
        self.editor.lock().map(|editor| editor.can_redo()).unwrap_or(false)
    }

    pub fn save_undo_state(&self) {
        if let Ok(mut editor) = self.editor.lock() {
            editor.save_undo_state();
        }
    }

    pub fn render_editor_spans(&self) -> Vec<MarkdownStyledSpan> {
        self.editor
            .lock()
            .map(|editor| {
                editor
                    .render_editor_spans()
                    .into_iter()
                    .map(MarkdownStyledSpan::from)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn set_text(&self, text: String) {
        if let Ok(mut editor) = self.editor.lock() {
            editor.set_text(text);
        }
    }

    pub fn insert_text(&self, text: String) -> Result<()> {
        Ok(self.lock_editor()?.insert_text(&text)?)
    }

    pub fn delete_range(&self, start: u32, end: u32) -> Result<()> {
        Ok(self.lock_editor()?.delete_range(start, end)?)
    }

    pub fn delete_selection(&self) -> Result<bool> {
        Ok(self.lock_editor()?.delete_selection()?)
    }

    pub fn replace_range(&self, start: u32, end: u32, text: String) -> Result<()> {
        Ok(self.lock_editor()?.replace_range(start, end, &text)?)
    }
}

impl MarkdownEditor {
    fn lock_editor(&self) -> Result<MutexGuard<'_, CommonMarkdownEditor>> {
        self.editor
            .lock()
            .map_err(|_| MarkdownError::InvalidOperation("Markdown editor lock is poisoned".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_markdown_document_maps_safe_and_unsafe_links() {
        let document =
            parse_markdown_document("[safe](https://example.com) [unsafe](javascript:alert(1))".to_string()).unwrap();

        assert!(document.nodes.iter().any(|node| {
            matches!(
                (&node.kind, &node.safe_link),
                (
                    MarkdownNodeKind::Link,
                    Some(MarkdownSafeLink {
                        href,
                        scheme: MarkdownLinkScheme::Https,
                    })
                ) if href == "https://example.com"
            )
        }));
        assert!(document.nodes.iter().any(|node| {
            matches!(
                (&node.kind, &node.unsafe_link),
                (
                    MarkdownNodeKind::Link,
                    Some(MarkdownUnsafeLink {
                        raw,
                        reason: MarkdownUnsafeLinkReason::UnsupportedScheme,
                    })
                ) if raw == "javascript:alert(1)"
            )
        }));
    }

    #[test]
    fn parse_markdown_document_matches_shared_fixture_contract() {
        let text = include_str!("../../proton-pass-common/test_data/markdown/shared_renderer.md");
        let document = parse_markdown_document(text.to_string()).unwrap();

        assert_eq!(document.root.len(), 6);
        assert!(document
            .nodes
            .iter()
            .any(|node| matches!(node.kind, MarkdownNodeKind::Heading) && node.level == Some(1)));
        assert!(document
            .nodes
            .iter()
            .any(|node| matches!(node.kind, MarkdownNodeKind::Strong)));
        assert!(document.nodes.iter().any(|node| {
            matches!(
                (&node.kind, &node.safe_link),
                (
                    MarkdownNodeKind::Link,
                    Some(MarkdownSafeLink {
                        href,
                        scheme: MarkdownLinkScheme::Https,
                    })
                ) if href == "HTTPS://Example.COM/Path"
            )
        }));
        assert!(document.nodes.iter().any(|node| {
            matches!(
                (&node.kind, &node.unsafe_link),
                (
                    MarkdownNodeKind::Link,
                    Some(MarkdownUnsafeLink {
                        raw,
                        reason: MarkdownUnsafeLinkReason::UnsupportedScheme,
                    })
                ) if raw == "javascript:alert(1)"
            )
        }));
        assert!(document.nodes.iter().any(|node| {
            matches!(
                (&node.kind, &node.language, &node.text),
                (MarkdownNodeKind::CodeBlock, Some(language), Some(code))
                    if language == "rust" && code == "fn main() {\n    println!(\"hi\");\n}\n"
            )
        }));

        let rendered_text = document
            .nodes
            .iter()
            .filter_map(|node| node.text.as_deref())
            .collect::<String>();
        assert!(rendered_text.contains("<kbd>Enter</kbd>"));
    }

    #[test]
    fn poisoned_lock_returns_error_instead_of_panicking() {
        let editor = MarkdownEditor::new("text".to_string());
        let poisoned_editor = editor.editor.clone();

        let _ = std::panic::catch_unwind(move || {
            let _guard = poisoned_editor.lock().unwrap();
            panic!("poison markdown editor lock");
        });

        assert!(matches!(
            editor.set_cursor(0),
            Err(MarkdownError::InvalidOperation(message)) if message.contains("poisoned")
        ));
        assert_eq!(editor.render_editor_spans(), Vec::<MarkdownStyledSpan>::new());
    }

    #[test]
    fn poisoned_lock_read_methods_return_safe_defaults() {
        // Per the README contract: "read-only helpers return safe defaults" on a poisoned lock.
        // Write methods surface MarkdownError::InvalidOperation.
        // This test documents and pins that asymmetry so any future change is explicit.
        let editor = MarkdownEditor::new("some content".to_string());
        editor.set_cursor(4).unwrap();
        let poisoned_editor = editor.editor.clone();

        let _ = std::panic::catch_unwind(move || {
            let _guard = poisoned_editor.lock().unwrap();
            panic!("poison markdown editor lock");
        });

        // Read-only helpers: safe defaults (documented behavior)
        assert_eq!(editor.get_text(), "", "get_text returns empty string on poisoned lock");
        assert_eq!(editor.get_cursor(), 0, "get_cursor returns 0 on poisoned lock");
        assert_eq!(
            editor.get_selection(),
            None,
            "get_selection returns None on poisoned lock"
        );
        assert!(!editor.can_undo(), "can_undo returns false on poisoned lock");
        assert!(!editor.can_redo(), "can_redo returns false on poisoned lock");
        assert_eq!(editor.render_editor_spans(), Vec::<MarkdownStyledSpan>::new());

        // Write methods surface the error
        assert!(matches!(
            editor.apply_operation(MarkdownOperation::Bold),
            Err(MarkdownError::InvalidOperation(_))
        ));
        assert!(matches!(
            editor.set_selection(0, 4),
            Err(MarkdownError::InvalidOperation(_))
        ));
    }
}
