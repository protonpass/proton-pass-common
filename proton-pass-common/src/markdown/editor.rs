use super::cursor::CursorUtils;
use super::list_operations::ListOperations;
use super::newline::NewlineHandler;
use super::operations::MarkdownOperations;
use super::renderer::{render_editor_spans, StyledSpan};
use super::undo::{EditorState, UndoStack};
use super::utf16;
use super::{MarkdownError, Operation, Result};

/// The main markdown editor with undo/redo support
///
/// **Important**: This editor uses UTF-8 byte offsets internally for all operations,
/// but the public API accepts and returns UTF-16 code unit offsets to match the native
/// string indexing in Kotlin, Swift, and TypeScript/JavaScript.
///
/// All conversions between UTF-8 and UTF-16 happen at the API boundary.
#[derive(Debug, Clone)]
pub struct MarkdownEditor {
    // Internal state uses UTF-8 byte offsets
    text: String,
    cursor: u32,                   // UTF-8 byte offset
    selection: Option<(u32, u32)>, // UTF-8 byte offsets
    undo_stack: UndoStack,
}

struct OperationOutput {
    text: String,
    cursor_utf8: u32,
    selection_utf8: Option<(u32, u32)>,
}

impl MarkdownEditor {
    /// Create a new markdown editor with the given text
    pub fn new(text: String) -> Self {
        let cursor = text.len() as u32;
        Self {
            text,
            cursor,
            selection: None,
            undo_stack: UndoStack::new(100), // Max 100 undo levels
        }
    }

    /// Get the current text
    pub fn get_text(&self) -> &str {
        &self.text
    }

    /// Get the current cursor position (UTF-16 code unit offset)
    pub fn get_cursor(&self) -> u32 {
        utf16::utf8_to_utf16_offset(&self.text, self.cursor as usize) as u32
    }

    /// Get the current selection, if any (UTF-16 code unit offsets)
    pub fn get_selection(&self) -> Option<(u32, u32)> {
        self.selection.map(|(start, end)| {
            let start_utf16 = utf16::utf8_to_utf16_offset(&self.text, start as usize) as u32;
            let end_utf16 = utf16::utf8_to_utf16_offset(&self.text, end as usize) as u32;
            (start_utf16, end_utf16)
        })
    }

    /// Set the cursor position (accepts UTF-16 code unit offset)
    pub fn set_cursor(&mut self, position_utf16: u32) -> Result<()> {
        let pos = self.utf16_to_utf8_cursor(position_utf16)?;

        self.cursor = pos as u32;
        self.selection = None;
        Ok(())
    }

    /// Set the selection range (accepts UTF-16 code unit offsets)
    pub fn set_selection(&mut self, start_utf16: u32, end_utf16: u32) -> Result<()> {
        let start_pos = self.utf16_to_utf8_selection(start_utf16)?;
        let end_pos = self.utf16_to_utf8_selection(end_utf16)?;

        let (start, end) = CursorUtils::normalize_selection(start_pos, end_pos);
        self.cursor = end as u32;
        self.selection = if start == end {
            None
        } else {
            Some((start as u32, end as u32))
        };
        Ok(())
    }

    /// Set the entire text content (useful when syncing from native text input)
    /// This replaces all text and preserves the cursor position if valid.
    /// NOTE: Does NOT save state for undo - use this for syncing with native inputs
    /// where the user is typing. For programmatic changes that should be undoable,
    /// use text editing methods like insert_text() or apply_operation().
    pub fn set_text(&mut self, text: String) {
        let cursor_utf16 = self.get_cursor() as usize;
        let selection_utf16 = self.get_selection();
        self.text = text;
        self.cursor = self.clamp_utf16_to_utf8(cursor_utf16) as u32;
        self.selection = selection_utf16.and_then(|(start, end)| {
            let start = utf16::strict_utf16_to_utf8_offset(&self.text, start as usize)?;
            let end = utf16::strict_utf16_to_utf8_offset(&self.text, end as usize)?;
            if start == end {
                None
            } else {
                Some((start as u32, end as u32))
            }
        });
    }

    /// Insert text at the current cursor position
    /// Saves state for undo.
    pub fn insert_text(&mut self, text: &str) -> Result<()> {
        self.save_state();

        let cursor_pos = self.cursor as usize;

        // If there's a selection, replace it
        if let Some((start, end)) = self.selection {
            let start = start as usize;
            let end = end as usize;
            self.text.replace_range(start..end, text);
            self.cursor = (start + text.len()) as u32;
            self.selection = None;
        } else {
            // Insert at cursor
            if cursor_pos > self.text.len() {
                return Err(MarkdownError::InvalidCursorPosition(format!(
                    "Cursor position {} is beyond text length {}",
                    cursor_pos,
                    self.text.len()
                )));
            }

            self.text.insert_str(cursor_pos, text);
            self.cursor = (cursor_pos + text.len()) as u32;
        }

        Ok(())
    }

    /// Delete text in the given range
    /// Saves state for undo.
    pub fn delete_range(&mut self, start: u32, end: u32) -> Result<()> {
        let start_pos = self.utf16_to_utf8_selection(start)?;
        let end_pos = self.utf16_to_utf8_selection(end)?;
        self.delete_range_utf8(start_pos as u32, end_pos as u32)
    }

    /// Delete the current selection, if any
    /// Returns true if something was deleted, false if no selection.
    /// Saves state for undo if deletion occurs.
    pub fn delete_selection(&mut self) -> Result<bool> {
        if let Some((start, end)) = self.selection {
            self.delete_range_utf8(start, end)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Replace text in the given range with new text
    /// Saves state for undo.
    pub fn replace_range(&mut self, start: u32, end: u32, text: &str) -> Result<()> {
        let start_pos = self.utf16_to_utf8_selection(start)?;
        let end_pos = self.utf16_to_utf8_selection(end)?;
        self.replace_range_utf8(start_pos as u32, end_pos as u32, text)
    }

    /// Render the current markdown text to editor styled spans.
    pub fn render_editor_spans(&self) -> Vec<StyledSpan> {
        render_editor_spans(&self.text)
    }

    /// Apply a markdown operation
    pub fn apply_operation(&mut self, operation: Operation) -> Result<()> {
        // Determine the range to operate on
        let (start, end) = self.get_operation_range(operation)?;

        // Apply the operation
        let result = match operation {
            Operation::Bold
            | Operation::Italic
            | Operation::Strikethrough
            | Operation::Header(_)
            | Operation::Blockquote => MarkdownOperations::apply_inline_formatting(&self.text, start, end, operation),
            Operation::CreateOrderedList | Operation::CreateUnorderedList => {
                ListOperations::create_list(&self.text, start, end, operation)
            }
            Operation::IndentList => ListOperations::indent_list(&self.text, start, end),
            Operation::UnindentList => ListOperations::unindent_list(&self.text, start, end),
        };

        let (new_text, new_cursor, new_selection) = result?;
        self.apply_output_if_changed(OperationOutput {
            text: new_text,
            cursor_utf8: new_cursor,
            selection_utf8: new_selection,
        });

        Ok(())
    }

    /// Undo the last operation
    pub fn undo(&mut self) -> bool {
        let current_state = EditorState::new(self.text.clone(), self.cursor, self.selection);

        if let Some(prev_state) = self.undo_stack.undo(current_state) {
            // Extract string from Rc
            self.text = (*prev_state.text).clone();
            self.cursor = prev_state.cursor;
            self.selection = prev_state.selection;
            true
        } else {
            false
        }
    }

    /// Redo the last undone operation
    pub fn redo(&mut self) -> bool {
        let current_state = EditorState::new(self.text.clone(), self.cursor, self.selection);

        if let Some(next_state) = self.undo_stack.redo(current_state) {
            // Extract string from Rc
            self.text = (*next_state.text).clone();
            self.cursor = next_state.cursor;
            self.selection = next_state.selection;
            true
        } else {
            false
        }
    }

    /// Check if undo is available
    pub fn can_undo(&self) -> bool {
        self.undo_stack.can_undo()
    }

    /// Check if redo is available
    pub fn can_redo(&self) -> bool {
        self.undo_stack.can_redo()
    }

    /// Manually save the current state to the undo stack
    /// Use this to create undo points for batched text input (e.g., after typing a word or sentence)
    pub fn save_undo_state(&mut self) {
        self.save_state();
    }

    /// Insert a newline at the current cursor position with smart list continuation
    /// If the cursor is in a list item, this will automatically add the next list marker
    pub fn insert_newline(&mut self) -> Result<()> {
        let cursor_pos = self.cursor as usize;
        let (new_text, new_cursor) = NewlineHandler::insert_newline(&self.text, cursor_pos)?;

        self.apply_output_if_changed(OperationOutput {
            text: new_text,
            cursor_utf8: new_cursor,
            selection_utf8: None,
        });

        Ok(())
    }

    /// Save the current state to the undo stack
    fn save_state(&mut self) {
        let state = EditorState::new(self.text.clone(), self.cursor, self.selection);
        self.undo_stack.push(state);
    }

    fn apply_output_if_changed(&mut self, output: OperationOutput) {
        let changed =
            output.text != self.text || output.cursor_utf8 != self.cursor || output.selection_utf8 != self.selection;

        if !changed {
            return;
        }

        self.save_state();
        self.text = output.text;
        self.cursor = output.cursor_utf8;
        self.selection = output.selection_utf8;
    }

    fn utf16_to_utf8_cursor(&self, position_utf16: u32) -> Result<usize> {
        utf16::strict_utf16_to_utf8_offset(&self.text, position_utf16 as usize).ok_or_else(|| {
            let text_utf16_len = self.text.encode_utf16().count();
            MarkdownError::InvalidCursorPosition(format!(
                "UTF-16 position {} is not a valid boundary for text with UTF-16 length {}",
                position_utf16, text_utf16_len
            ))
        })
    }

    fn utf16_to_utf8_selection(&self, position_utf16: u32) -> Result<usize> {
        utf16::strict_utf16_to_utf8_offset(&self.text, position_utf16 as usize).ok_or_else(|| {
            let text_utf16_len = self.text.encode_utf16().count();
            MarkdownError::InvalidSelection(format!(
                "UTF-16 selection position {} is not a valid boundary for text with UTF-16 length {}",
                position_utf16, text_utf16_len
            ))
        })
    }

    fn clamp_utf16_to_utf8(&self, utf16_offset: usize) -> usize {
        let max_utf16 = self.text.encode_utf16().count();
        let mut candidate = utf16_offset.min(max_utf16);

        loop {
            if let Some(utf8_offset) = utf16::strict_utf16_to_utf8_offset(&self.text, candidate) {
                return utf8_offset;
            }
            candidate = candidate.saturating_sub(1);
        }
    }

    fn delete_range_utf8(&mut self, start: u32, end: u32) -> Result<()> {
        let start_pos = start as usize;
        let end_pos = end as usize;
        self.validate_utf8_range(start_pos, end_pos)?;

        self.save_state();
        self.text.replace_range(start_pos..end_pos, "");
        self.cursor = start;
        self.selection = None;

        Ok(())
    }

    fn replace_range_utf8(&mut self, start: u32, end: u32, text: &str) -> Result<()> {
        let start_pos = start as usize;
        let end_pos = end as usize;
        self.validate_utf8_range(start_pos, end_pos)?;

        self.save_state();
        self.text.replace_range(start_pos..end_pos, text);
        self.cursor = (start_pos + text.len()) as u32;
        self.selection = None;

        Ok(())
    }

    fn validate_utf8_range(&self, start_pos: usize, end_pos: usize) -> Result<()> {
        if start_pos > self.text.len() || end_pos > self.text.len() {
            return Err(MarkdownError::InvalidSelection(format!(
                "Range ({}, {}) is beyond text length {}",
                start_pos,
                end_pos,
                self.text.len()
            )));
        }

        if start_pos > end_pos {
            return Err(MarkdownError::InvalidSelection(
                "Start position is greater than end position".to_string(),
            ));
        }

        if !self.text.is_char_boundary(start_pos) || !self.text.is_char_boundary(end_pos) {
            return Err(MarkdownError::InvalidSelection(
                "Range is not at valid character boundaries".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the range for the current operation
    /// Handles selection, word boundaries, and line boundaries as appropriate
    fn get_operation_range(&self, operation: Operation) -> Result<(usize, usize)> {
        match self.selection {
            Some((start, end)) => Ok((start as usize, end as usize)),
            None => {
                // No selection - determine range based on operation
                let cursor_pos = self.cursor as usize;

                match operation {
                    Operation::Bold | Operation::Italic | Operation::Strikethrough => {
                        // If the cursor is inside a word, format the word. Otherwise insert
                        // paired markers and leave the cursor between them for new text.
                        Ok(CursorUtils::find_word_containing_cursor(&self.text, cursor_pos)
                            .unwrap_or((cursor_pos, cursor_pos)))
                    }
                    Operation::Header(_)
                    | Operation::CreateOrderedList
                    | Operation::CreateUnorderedList
                    | Operation::IndentList
                    | Operation::UnindentList
                    | Operation::Blockquote => {
                        // For block operations, find line boundaries
                        Ok(CursorUtils::find_line_boundaries(&self.text, cursor_pos))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_editor() {
        let editor = MarkdownEditor::new("hello world".to_string());
        assert_eq!(editor.get_text(), "hello world");
        assert_eq!(editor.get_cursor(), 11);
        assert_eq!(editor.get_selection(), None);
    }

    #[test]
    fn test_set_cursor() {
        let mut editor = MarkdownEditor::new("hello world".to_string());
        editor.set_cursor(5).unwrap();
        assert_eq!(editor.get_cursor(), 5);
    }

    #[test]
    fn test_set_cursor_invalid() {
        let mut editor = MarkdownEditor::new("hello".to_string());
        assert!(editor.set_cursor(100).is_err());
    }

    #[test]
    fn test_set_cursor_rejects_middle_of_surrogate_pair() {
        let mut editor = MarkdownEditor::new("a😀b".to_string());
        assert!(editor.set_cursor(2).is_err());
    }

    #[test]
    fn test_set_selection() {
        let mut editor = MarkdownEditor::new("hello world".to_string());
        editor.set_selection(0, 5).unwrap();
        assert_eq!(editor.get_selection(), Some((0, 5)));
    }

    #[test]
    fn test_set_selection_normalized() {
        let mut editor = MarkdownEditor::new("hello world".to_string());
        editor.set_selection(5, 0).unwrap();
        assert_eq!(editor.get_selection(), Some((0, 5)));
    }

    #[test]
    fn test_delete_range_uses_utf16_offsets() {
        let mut editor = MarkdownEditor::new("a😀b".to_string());
        editor.delete_range(1, 3).unwrap();

        assert_eq!(editor.get_text(), "ab");
        assert_eq!(editor.get_cursor(), 1);
    }

    #[test]
    fn test_replace_range_uses_utf16_offsets() {
        let mut editor = MarkdownEditor::new("a😀b".to_string());
        editor.replace_range(1, 3, "x").unwrap();

        assert_eq!(editor.get_text(), "axb");
        assert_eq!(editor.get_cursor(), 2);
    }

    #[test]
    fn test_delete_selection_uses_internal_utf8_offsets() {
        let mut editor = MarkdownEditor::new("a😀b".to_string());
        editor.set_selection(1, 3).unwrap();

        assert!(editor.delete_selection().unwrap());
        assert_eq!(editor.get_text(), "ab");
        assert_eq!(editor.get_cursor(), 1);
    }

    #[test]
    fn test_set_text_preserves_cursor_by_utf16_offset() {
        let mut editor = MarkdownEditor::new("a😀b".to_string());
        editor.set_cursor(3).unwrap();
        editor.set_text("aébc".to_string());

        assert_eq!(editor.get_cursor(), 3);
    }

    #[test]
    fn test_render_editor_spans_basic() {
        let editor = MarkdownEditor::new("**bold** text".to_string());
        let spans = editor.render_editor_spans();
        assert!(!spans.is_empty());
    }

    #[test]
    fn test_render_editor_spans_uses_utf16_offsets() {
        let editor = MarkdownEditor::new("😀 **bold**".to_string());
        let spans = editor.render_editor_spans();

        let bold_span = spans
            .iter()
            .find(|span| matches!(span.style, super::super::SpanStyle::Bold))
            .unwrap();
        assert_eq!(bold_span.start, 3);
        assert_eq!(bold_span.end, 11);
    }

    #[test]
    fn test_inline_operation_at_collapsed_cursor_inserts_markers() {
        let cases = [
            (Operation::Bold, "hello ****world", 8),
            (Operation::Italic, "hello **world", 7),
            (Operation::Strikethrough, "hello ~~~~world", 8),
        ];

        for (operation, expected_text, expected_cursor) in cases {
            let mut editor = MarkdownEditor::new("hello world".to_string());
            editor.set_cursor(6).unwrap();

            editor.apply_operation(operation).unwrap();

            assert_eq!(editor.get_text(), expected_text);
            assert_eq!(editor.get_cursor(), expected_cursor);
            assert_eq!(editor.get_selection(), None);
            assert!(editor.can_undo());
        }
    }

    #[test]
    fn test_inline_operation_inside_word_formats_word() {
        let cases = [
            (Operation::Bold, "**palabra**", 9),
            (Operation::Italic, "*palabra*", 8),
            (Operation::Strikethrough, "~~palabra~~", 9),
        ];

        for (operation, expected_text, expected_cursor) in cases {
            let mut editor = MarkdownEditor::new("palabra".to_string());
            editor.set_cursor(4).unwrap();

            editor.apply_operation(operation).unwrap();

            assert_eq!(editor.get_text(), expected_text);
            assert_eq!(editor.get_cursor(), expected_cursor);
            assert_eq!(editor.get_selection(), None);
            assert!(editor.can_undo());
        }
    }

    #[test]
    fn test_inline_operation_at_empty_document_inserts_markers() {
        let mut editor = MarkdownEditor::new(String::new());

        editor.apply_operation(Operation::Bold).unwrap();

        assert_eq!(editor.get_text(), "****");
        assert_eq!(editor.get_cursor(), 2);
        assert_eq!(editor.get_selection(), None);
        assert!(editor.can_undo());
    }

    #[test]
    fn test_header_operation_at_empty_document_inserts_prefix() {
        let mut editor = MarkdownEditor::new(String::new());

        editor.apply_operation(Operation::Header(2)).unwrap();

        assert_eq!(editor.get_text(), "## ");
        assert_eq!(editor.get_cursor(), 3);
        assert_eq!(editor.get_selection(), None);
        assert!(editor.can_undo());
    }

    #[test]
    fn test_header_operation_on_empty_line_inserts_prefix() {
        let mut editor = MarkdownEditor::new("before\n\nafter".to_string());
        editor.set_cursor(7).unwrap();

        editor.apply_operation(Operation::Header(3)).unwrap();

        assert_eq!(editor.get_text(), "before\n### \nafter");
        assert_eq!(editor.get_cursor(), 11);
        assert_eq!(editor.get_selection(), None);
        assert!(editor.can_undo());
    }

    #[test]
    fn test_noop_list_operation_does_not_create_undo_entry() {
        let mut editor = MarkdownEditor::new("plain text".to_string());

        editor.apply_operation(Operation::IndentList).unwrap();

        assert_eq!(editor.get_text(), "plain text");
        assert!(!editor.can_undo());
    }

    #[test]
    fn test_invalid_operation_does_not_create_undo_entry() {
        let mut editor = MarkdownEditor::new("plain text".to_string());

        assert!(editor.apply_operation(Operation::Header(7)).is_err());

        assert_eq!(editor.get_text(), "plain text");
        assert!(!editor.can_undo());
    }
}
