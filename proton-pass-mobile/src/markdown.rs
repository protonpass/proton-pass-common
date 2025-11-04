use proton_pass_common::markdown::{
    MarkdownEditor as CommonMarkdownEditor, MarkdownError as CommonMarkdownError, Operation as CommonOperation,
    SpanStyle as CommonSpanStyle, StyledSpan as CommonStyledSpan,
};
use std::sync::{Arc, Mutex};

// START MAPPING TYPES

#[derive(Debug, proton_pass_derive::Error)]
pub enum MarkdownError {
    InvalidCursorPosition(String),
    InvalidSelection(String),
    InvalidHeaderLevel(String),
    InvalidOperation(String),
    ParsingError(String),
}

impl From<CommonMarkdownError> for MarkdownError {
    fn from(e: CommonMarkdownError) -> Self {
        match e {
            CommonMarkdownError::InvalidCursorPosition(s) => MarkdownError::InvalidCursorPosition(s),
            CommonMarkdownError::InvalidSelection(s) => MarkdownError::InvalidSelection(s),
            CommonMarkdownError::InvalidHeaderLevel(s) => MarkdownError::InvalidHeaderLevel(s),
            CommonMarkdownError::InvalidOperation(s) => MarkdownError::InvalidOperation(s),
            CommonMarkdownError::ParsingError(s) => MarkdownError::ParsingError(s),
        }
    }
}

type Result<T> = std::result::Result<T, MarkdownError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq)]
pub struct MarkdownStyledSpan {
    pub start: u32,
    pub end: u32,
    pub style: MarkdownSpanStyle,
    pub level: Option<u8>,
    pub number: Option<u32>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MarkdownSelection {
    pub start: u32,
    pub end: u32,
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

// END MAPPING TYPES

pub struct MarkdownEditor {
    editor: Arc<Mutex<CommonMarkdownEditor>>,
}

impl MarkdownEditor {
    pub fn new(text: String) -> Self {
        Self {
            editor: Arc::new(Mutex::new(CommonMarkdownEditor::new(text))),
        }
    }

    pub fn get_text(&self) -> String {
        self.editor.lock().unwrap().get_text().to_string()
    }

    pub fn get_cursor(&self) -> u32 {
        self.editor.lock().unwrap().get_cursor()
    }

    pub fn get_selection(&self) -> Option<MarkdownSelection> {
        self.editor
            .lock()
            .unwrap()
            .get_selection()
            .map(|(start, end)| MarkdownSelection { start, end })
    }

    pub fn set_cursor(&self, position: u32) -> Result<()> {
        Ok(self.editor.lock().unwrap().set_cursor(position)?)
    }

    pub fn set_selection(&self, start: u32, end: u32) -> Result<()> {
        Ok(self.editor.lock().unwrap().set_selection(start, end)?)
    }

    pub fn apply_operation(&self, operation: MarkdownOperation) -> Result<()> {
        Ok(self.editor.lock().unwrap().apply_operation(operation.into())?)
    }

    pub fn insert_newline(&self) -> Result<()> {
        Ok(self.editor.lock().unwrap().insert_newline()?)
    }

    pub fn undo(&self) -> bool {
        self.editor.lock().unwrap().undo()
    }

    pub fn redo(&self) -> bool {
        self.editor.lock().unwrap().redo()
    }

    pub fn can_undo(&self) -> bool {
        self.editor.lock().unwrap().can_undo()
    }

    pub fn can_redo(&self) -> bool {
        self.editor.lock().unwrap().can_redo()
    }

    pub fn save_undo_state(&self) {
        self.editor.lock().unwrap().save_undo_state();
    }

    pub fn render(&self) -> Vec<MarkdownStyledSpan> {
        self.editor
            .lock()
            .unwrap()
            .render()
            .into_iter()
            .map(MarkdownStyledSpan::from)
            .collect()
    }

    pub fn set_text(&self, text: String) {
        self.editor.lock().unwrap().set_text(text);
    }

    pub fn insert_text(&self, text: String) -> Result<()> {
        Ok(self.editor.lock().unwrap().insert_text(&text)?)
    }

    pub fn delete_range(&self, start: u32, end: u32) -> Result<()> {
        Ok(self.editor.lock().unwrap().delete_range(start, end)?)
    }

    pub fn delete_selection(&self) -> Result<bool> {
        Ok(self.editor.lock().unwrap().delete_selection()?)
    }

    pub fn replace_range(&self, start: u32, end: u32, text: String) -> Result<()> {
        Ok(self.editor.lock().unwrap().replace_range(start, end, &text)?)
    }
}
