use markdown_types::{
    WasmMarkdownDocument, WasmMarkdownLinkScheme, WasmMarkdownNode, WasmMarkdownNodeKind, WasmMarkdownOperation,
    WasmMarkdownSafeLink, WasmMarkdownSelection, WasmMarkdownSpanStyle, WasmMarkdownStyledSpan, WasmMarkdownUnsafeLink,
    WasmMarkdownUnsafeLinkReason,
};
use proton_pass_common::markdown::{
    parse_markdown_document, MarkdownDocument as CommonMarkdownDocument, MarkdownEditor as CommonMarkdownEditor,
    MarkdownLink as CommonMarkdownLink, MarkdownLinkScheme as CommonMarkdownLinkScheme,
    MarkdownNode as CommonMarkdownNode, MarkdownNodeKind as CommonMarkdownNodeKind,
    MarkdownUnsafeLinkReason as CommonMarkdownUnsafeLinkReason, Operation as CommonOperation,
    SpanStyle as CommonSpanStyle, StyledSpan as CommonStyledSpan,
};
use wasm_bindgen::prelude::*;

mod markdown_types;

#[wasm_bindgen(js_name = parseMarkdownDocument)]
pub fn parse_markdown_document_wasm(text: String) -> Result<WasmMarkdownDocument, JsError> {
    Ok(WasmMarkdownDocument::from(parse_markdown_document(&text)?))
}

/// A markdown editor with undo/redo support
#[wasm_bindgen]
pub struct MarkdownEditor {
    editor: CommonMarkdownEditor,
}

#[wasm_bindgen]
impl MarkdownEditor {
    /// Create a new markdown editor with the given text
    #[wasm_bindgen(constructor)]
    pub fn new(text: String) -> Self {
        Self {
            editor: CommonMarkdownEditor::new(text),
        }
    }

    /// Get the current text
    #[wasm_bindgen(js_name = getText)]
    pub fn get_text(&self) -> String {
        self.editor.get_text().to_string()
    }

    /// Get the current cursor position
    #[wasm_bindgen(js_name = getCursor)]
    pub fn get_cursor(&self) -> u32 {
        self.editor.get_cursor()
    }

    /// Set the cursor position
    #[wasm_bindgen(js_name = setCursor)]
    pub fn set_cursor(&mut self, position: u32) -> Result<(), JsError> {
        Ok(self.editor.set_cursor(position)?)
    }

    /// Set the selection range
    #[wasm_bindgen(js_name = setSelection)]
    pub fn set_selection(&mut self, start: u32, end: u32) -> Result<(), JsError> {
        Ok(self.editor.set_selection(start, end)?)
    }

    /// Get the current selection, if any (UTF-16 code unit offsets)
    #[wasm_bindgen(js_name = getSelection)]
    pub fn get_selection(&self) -> Option<WasmMarkdownSelection> {
        self.editor
            .get_selection()
            .map(|(start, end)| WasmMarkdownSelection { start, end })
    }

    /// Apply a markdown operation
    #[wasm_bindgen(js_name = applyOperation)]
    pub fn apply_operation(&mut self, operation: WasmMarkdownOperation) -> Result<(), JsError> {
        let common_op: CommonOperation = operation.into();
        Ok(self.editor.apply_operation(common_op)?)
    }

    /// Insert a newline with smart list continuation
    #[wasm_bindgen(js_name = insertNewline)]
    pub fn insert_newline(&mut self) -> Result<(), JsError> {
        Ok(self.editor.insert_newline()?)
    }

    /// Set the entire text content (useful for syncing with native text input)
    #[wasm_bindgen(js_name = setText)]
    pub fn set_text(&mut self, text: String) {
        self.editor.set_text(text);
    }

    /// Insert text at the current cursor position
    #[wasm_bindgen(js_name = insertText)]
    pub fn insert_text(&mut self, text: String) -> Result<(), JsError> {
        Ok(self.editor.insert_text(&text)?)
    }

    /// Delete text in the given range
    #[wasm_bindgen(js_name = deleteRange)]
    pub fn delete_range(&mut self, start: u32, end: u32) -> Result<(), JsError> {
        Ok(self.editor.delete_range(start, end)?)
    }

    /// Delete the current selection, if any
    #[wasm_bindgen(js_name = deleteSelection)]
    pub fn delete_selection(&mut self) -> Result<bool, JsError> {
        Ok(self.editor.delete_selection()?)
    }

    /// Replace text in the given range
    #[wasm_bindgen(js_name = replaceRange)]
    pub fn replace_range(&mut self, start: u32, end: u32, text: String) -> Result<(), JsError> {
        Ok(self.editor.replace_range(start, end, &text)?)
    }

    /// Undo the last operation
    pub fn undo(&mut self) -> bool {
        self.editor.undo()
    }

    /// Redo the last undone operation
    pub fn redo(&mut self) -> bool {
        self.editor.redo()
    }

    /// Check if undo is available
    #[wasm_bindgen(js_name = canUndo)]
    pub fn can_undo(&self) -> bool {
        self.editor.can_undo()
    }

    /// Check if redo is available
    #[wasm_bindgen(js_name = canRedo)]
    pub fn can_redo(&self) -> bool {
        self.editor.can_redo()
    }

    /// Manually save the current state to the undo stack
    /// Use this to create undo points for batched text input (e.g., after typing a word or sentence)
    #[wasm_bindgen(js_name = saveUndoState)]
    pub fn save_undo_state(&mut self) {
        self.editor.save_undo_state();
    }

    /// Render the current markdown text to editor styled spans
    #[wasm_bindgen(js_name = renderEditorSpans)]
    pub fn render_editor_spans(&self) -> Vec<WasmMarkdownStyledSpan> {
        self.editor
            .render_editor_spans()
            .into_iter()
            .map(WasmMarkdownStyledSpan::from)
            .collect()
    }
}

// Helper function conversions
impl From<CommonStyledSpan> for WasmMarkdownStyledSpan {
    fn from(span: CommonStyledSpan) -> Self {
        let (style, level, number, url) = match span.style {
            CommonSpanStyle::Bold => (WasmMarkdownSpanStyle::Bold, None, None, None),
            CommonSpanStyle::Italic => (WasmMarkdownSpanStyle::Italic, None, None, None),
            CommonSpanStyle::Strikethrough => (WasmMarkdownSpanStyle::Strikethrough, None, None, None),
            CommonSpanStyle::Header(level) => {
                let style = match level {
                    1 => WasmMarkdownSpanStyle::Header1,
                    2 => WasmMarkdownSpanStyle::Header2,
                    3 => WasmMarkdownSpanStyle::Header3,
                    4 => WasmMarkdownSpanStyle::Header4,
                    5 => WasmMarkdownSpanStyle::Header5,
                    6 => WasmMarkdownSpanStyle::Header6,
                    _ => WasmMarkdownSpanStyle::Header1,
                };
                (style, Some(level), None, None)
            }
            CommonSpanStyle::Code => (WasmMarkdownSpanStyle::Code, None, None, None),
            CommonSpanStyle::CodeBlock => (WasmMarkdownSpanStyle::CodeBlock, None, None, None),
            CommonSpanStyle::Link { url } => (WasmMarkdownSpanStyle::Link, None, None, Some(url)),
            CommonSpanStyle::OrderedListItem { level, number } => {
                (WasmMarkdownSpanStyle::OrderedListItem, Some(level), Some(number), None)
            }
            CommonSpanStyle::UnorderedListItem { level } => {
                (WasmMarkdownSpanStyle::UnorderedListItem, Some(level), None, None)
            }
            CommonSpanStyle::Blockquote => (WasmMarkdownSpanStyle::Blockquote, None, None, None),
            CommonSpanStyle::MarkdownMarker => (WasmMarkdownSpanStyle::MarkdownMarker, None, None, None),
        };

        WasmMarkdownStyledSpan {
            start: span.start,
            end: span.end,
            style,
            level,
            number,
            url,
        }
    }
}

impl From<CommonMarkdownDocument> for WasmMarkdownDocument {
    fn from(document: CommonMarkdownDocument) -> Self {
        Self {
            nodes: document.nodes.into_iter().map(WasmMarkdownNode::from).collect(),
            root: document.root.into_iter().map(|id| id.0).collect(),
        }
    }
}

impl From<CommonMarkdownNode> for WasmMarkdownNode {
    fn from(node: CommonMarkdownNode) -> Self {
        let mut wasm_node = WasmMarkdownNode {
            id: node.id.0,
            parent_id: node.parent.map(|id| id.0),
            children: node.children.into_iter().map(|id| id.0).collect(),
            kind: WasmMarkdownNodeKind::Paragraph,
            text: None,
            level: None,
            start_number: None,
            language: None,
            title: None,
            safe_link: None,
            unsafe_link: None,
        };

        match node.kind {
            CommonMarkdownNodeKind::Paragraph => wasm_node.kind = WasmMarkdownNodeKind::Paragraph,
            CommonMarkdownNodeKind::Heading { level } => {
                wasm_node.kind = WasmMarkdownNodeKind::Heading;
                wasm_node.level = Some(level);
            }
            CommonMarkdownNodeKind::Text(text) => {
                wasm_node.kind = WasmMarkdownNodeKind::Text;
                wasm_node.text = Some(text);
            }
            CommonMarkdownNodeKind::Strong => wasm_node.kind = WasmMarkdownNodeKind::Strong,
            CommonMarkdownNodeKind::Emphasis => wasm_node.kind = WasmMarkdownNodeKind::Emphasis,
            CommonMarkdownNodeKind::Strikethrough => wasm_node.kind = WasmMarkdownNodeKind::Strikethrough,
            CommonMarkdownNodeKind::InlineCode(code) => {
                wasm_node.kind = WasmMarkdownNodeKind::InlineCode;
                wasm_node.text = Some(code);
            }
            CommonMarkdownNodeKind::CodeBlock { language, code } => {
                wasm_node.kind = WasmMarkdownNodeKind::CodeBlock;
                wasm_node.language = language;
                wasm_node.text = Some(code);
            }
            CommonMarkdownNodeKind::Link { destination, title } => {
                wasm_node.kind = WasmMarkdownNodeKind::Link;
                wasm_node.title = title;
                match destination {
                    CommonMarkdownLink::Safe { href, scheme } => {
                        wasm_node.safe_link = Some(WasmMarkdownSafeLink {
                            href,
                            scheme: WasmMarkdownLinkScheme::from(scheme),
                        });
                    }
                    CommonMarkdownLink::Unsafe { raw, reason } => {
                        wasm_node.unsafe_link = Some(WasmMarkdownUnsafeLink {
                            raw,
                            reason: WasmMarkdownUnsafeLinkReason::from(reason),
                        });
                    }
                }
            }
            CommonMarkdownNodeKind::Blockquote => wasm_node.kind = WasmMarkdownNodeKind::Blockquote,
            CommonMarkdownNodeKind::OrderedList { start } => {
                wasm_node.kind = WasmMarkdownNodeKind::OrderedList;
                wasm_node.start_number = Some(start);
            }
            CommonMarkdownNodeKind::UnorderedList => wasm_node.kind = WasmMarkdownNodeKind::UnorderedList,
            CommonMarkdownNodeKind::ListItem => wasm_node.kind = WasmMarkdownNodeKind::ListItem,
        }

        wasm_node
    }
}

impl From<CommonMarkdownLinkScheme> for WasmMarkdownLinkScheme {
    fn from(scheme: CommonMarkdownLinkScheme) -> Self {
        match scheme {
            CommonMarkdownLinkScheme::Http => WasmMarkdownLinkScheme::Http,
            CommonMarkdownLinkScheme::Https => WasmMarkdownLinkScheme::Https,
            CommonMarkdownLinkScheme::Mailto => WasmMarkdownLinkScheme::Mailto,
        }
    }
}

impl From<CommonMarkdownUnsafeLinkReason> for WasmMarkdownUnsafeLinkReason {
    fn from(reason: CommonMarkdownUnsafeLinkReason) -> Self {
        match reason {
            CommonMarkdownUnsafeLinkReason::Empty => WasmMarkdownUnsafeLinkReason::Empty,
            CommonMarkdownUnsafeLinkReason::UnsupportedScheme => WasmMarkdownUnsafeLinkReason::UnsupportedScheme,
            CommonMarkdownUnsafeLinkReason::ControlCharacter => WasmMarkdownUnsafeLinkReason::ControlCharacter,
            CommonMarkdownUnsafeLinkReason::UserInfo => WasmMarkdownUnsafeLinkReason::UserInfo,
            CommonMarkdownUnsafeLinkReason::RelativeOrFragment => WasmMarkdownUnsafeLinkReason::RelativeOrFragment,
            CommonMarkdownUnsafeLinkReason::Malformed => WasmMarkdownUnsafeLinkReason::Malformed,
        }
    }
}

impl From<WasmMarkdownOperation> for CommonOperation {
    fn from(op: WasmMarkdownOperation) -> Self {
        match op {
            WasmMarkdownOperation::Bold => CommonOperation::Bold,
            WasmMarkdownOperation::Italic => CommonOperation::Italic,
            WasmMarkdownOperation::Strikethrough => CommonOperation::Strikethrough,
            WasmMarkdownOperation::Header1 => CommonOperation::Header(1),
            WasmMarkdownOperation::Header2 => CommonOperation::Header(2),
            WasmMarkdownOperation::Header3 => CommonOperation::Header(3),
            WasmMarkdownOperation::Header4 => CommonOperation::Header(4),
            WasmMarkdownOperation::Header5 => CommonOperation::Header(5),
            WasmMarkdownOperation::Header6 => CommonOperation::Header(6),
            WasmMarkdownOperation::CreateOrderedList => CommonOperation::CreateOrderedList,
            WasmMarkdownOperation::CreateUnorderedList => CommonOperation::CreateUnorderedList,
            WasmMarkdownOperation::IndentList => CommonOperation::IndentList,
            WasmMarkdownOperation::UnindentList => CommonOperation::UnindentList,
            WasmMarkdownOperation::Blockquote => CommonOperation::Blockquote,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_selection_is_present_on_wasm_editor() {
        let mut editor = MarkdownEditor::new("hello world".to_string());
        editor.set_selection(0, 5).unwrap();
        assert_eq!(editor.get_selection(), Some(WasmMarkdownSelection { start: 0, end: 5 }));

        editor.set_cursor(3).unwrap();
        assert_eq!(editor.get_selection(), None);
    }
}
