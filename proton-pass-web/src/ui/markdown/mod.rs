use markdown_types::{WasmMarkdownOperation, WasmMarkdownSpanStyle, WasmMarkdownStyledSpan};
use proton_pass_common::markdown::{
    MarkdownEditor as CommonMarkdownEditor, Operation as CommonOperation, SpanStyle as CommonSpanStyle,
    StyledSpan as CommonStyledSpan,
};
use pulldown_cmark::{html, Options, Parser};
use wasm_bindgen::prelude::*;

mod markdown_types;

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

    /// Render the current markdown text to styled spans
    pub fn render(&self) -> Vec<WasmMarkdownStyledSpan> {
        self.editor
            .render()
            .into_iter()
            .map(WasmMarkdownStyledSpan::from)
            .collect()
    }

    /// Render the current markdown text to HTML
    /// This is a convenience method for web that converts markdown directly to HTML
    #[wasm_bindgen(js_name = renderToHtml)]
    pub fn render_to_html(&self) -> String {
        let text = self.editor.get_text();
        let mut options = Options::empty();
        options.insert(Options::ENABLE_STRIKETHROUGH);
        options.insert(Options::ENABLE_TABLES);
        options.insert(Options::ENABLE_FOOTNOTES);
        options.insert(Options::ENABLE_TASKLISTS);

        let parser = Parser::new_ext(text, options);
        let mut html_output = String::new();
        html::push_html(&mut html_output, parser);
        html_output
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
