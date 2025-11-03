use super::cursor::CursorUtils;
use super::list_operations::ListOperations;
use super::newline::NewlineHandler;
use super::operations::MarkdownOperations;
use super::renderer::{render_markdown, StyledSpan};
use super::undo::{EditorState, UndoStack};
use super::{MarkdownError, Operation, Result};

/// The main markdown editor with undo/redo support
#[derive(Debug, Clone)]
pub struct MarkdownEditor {
    text: String,
    cursor: u32,
    selection: Option<(u32, u32)>,
    undo_stack: UndoStack,
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

    /// Get the current cursor position
    pub fn get_cursor(&self) -> u32 {
        self.cursor
    }

    /// Get the current selection, if any
    pub fn get_selection(&self) -> Option<(u32, u32)> {
        self.selection
    }

    /// Set the cursor position
    pub fn set_cursor(&mut self, position: u32) -> Result<()> {
        let pos = position as usize;
        if pos > self.text.len() {
            return Err(MarkdownError::InvalidCursorPosition(format!(
                "Position {} is beyond text length {}",
                position,
                self.text.len()
            )));
        }

        if !CursorUtils::is_char_boundary(&self.text, pos) {
            return Err(MarkdownError::InvalidCursorPosition(
                "Position is not at a valid UTF-8 character boundary".to_string(),
            ));
        }

        self.cursor = position;
        self.selection = None;
        Ok(())
    }

    /// Set the selection range
    pub fn set_selection(&mut self, start: u32, end: u32) -> Result<()> {
        let start_pos = start as usize;
        let end_pos = end as usize;

        if start_pos > self.text.len() || end_pos > self.text.len() {
            return Err(MarkdownError::InvalidSelection(format!(
                "Selection ({}, {}) is beyond text length {}",
                start,
                end,
                self.text.len()
            )));
        }

        if !CursorUtils::is_char_boundary(&self.text, start_pos) || !CursorUtils::is_char_boundary(&self.text, end_pos)
        {
            return Err(MarkdownError::InvalidSelection(
                "Selection is not at valid UTF-8 character boundaries".to_string(),
            ));
        }

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
    /// Saves state for undo.
    pub fn set_text(&mut self, text: String) {
        self.save_state();
        
        // Preserve cursor if it's still valid, otherwise move to end
        if (self.cursor as usize) > text.len() {
            self.cursor = text.len() as u32;
        }
        
        // Clear selection if it's no longer valid
        if let Some((start, end)) = self.selection {
            if (start as usize) > text.len() || (end as usize) > text.len() {
                self.selection = None;
            }
        }
        
        self.text = text;
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
        self.save_state();
        
        let start_pos = start as usize;
        let end_pos = end as usize;
        
        if start_pos > self.text.len() || end_pos > self.text.len() {
            return Err(MarkdownError::InvalidSelection(format!(
                "Range ({}, {}) is beyond text length {}",
                start, end, self.text.len()
            )));
        }
        
        if start_pos > end_pos {
            return Err(MarkdownError::InvalidSelection(
                "Start position is greater than end position".to_string(),
            ));
        }
        
        self.text.replace_range(start_pos..end_pos, "");
        self.cursor = start;
        self.selection = None;
        
        Ok(())
    }

    /// Delete the current selection, if any
    /// Returns true if something was deleted, false if no selection.
    /// Saves state for undo if deletion occurs.
    pub fn delete_selection(&mut self) -> Result<bool> {
        if let Some((start, end)) = self.selection {
            self.delete_range(start, end)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Replace text in the given range with new text
    /// Saves state for undo.
    pub fn replace_range(&mut self, start: u32, end: u32, text: &str) -> Result<()> {
        self.save_state();
        
        let start_pos = start as usize;
        let end_pos = end as usize;
        
        if start_pos > self.text.len() || end_pos > self.text.len() {
            return Err(MarkdownError::InvalidSelection(format!(
                "Range ({}, {}) is beyond text length {}",
                start, end, self.text.len()
            )));
        }
        
        if start_pos > end_pos {
            return Err(MarkdownError::InvalidSelection(
                "Start position is greater than end position".to_string(),
            ));
        }
        
        self.text.replace_range(start_pos..end_pos, text);
        self.cursor = (start_pos + text.len()) as u32;
        self.selection = None;
        
        Ok(())
    }

    /// Render the current markdown text to styled spans
    pub fn render(&self) -> Vec<StyledSpan> {
        render_markdown(&self.text)
    }

    /// Apply a markdown operation
    pub fn apply_operation(&mut self, operation: Operation) -> Result<()> {
        // Save current state for undo
        self.save_state();

        // Determine the range to operate on
        let (start, end) = self.get_operation_range(operation)?;

        // Apply the operation
        let result = match operation {
            Operation::Bold | Operation::Italic | Operation::Strikethrough | Operation::Header(_) | Operation::Blockquote => {
                MarkdownOperations::apply_inline_formatting(&self.text, start, end, operation)
            }
            Operation::CreateOrderedList | Operation::CreateUnorderedList => {
                ListOperations::create_list(&self.text, start, end, operation)
            }
            Operation::IndentList => ListOperations::indent_list(&self.text, start, end),
            Operation::UnindentList => ListOperations::unindent_list(&self.text, start, end),
        };

        match result {
            Ok((new_text, new_cursor, new_selection)) => {
                self.text = new_text;
                self.cursor = new_cursor;
                self.selection = new_selection;
                Ok(())
            }
            Err(e) => {
                // Restore state on error by undoing
                self.undo();
                Err(e)
            }
        }
    }

    /// Undo the last operation
    pub fn undo(&mut self) -> bool {
        let current_state = EditorState::new(self.text.clone(), self.cursor, self.selection);

        if let Some(prev_state) = self.undo_stack.undo(current_state) {
            self.text = prev_state.text;
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
            self.text = next_state.text;
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

    /// Insert a newline at the current cursor position with smart list continuation
    /// If the cursor is in a list item, this will automatically add the next list marker
    pub fn insert_newline(&mut self) -> Result<()> {
        // Save current state for undo
        self.save_state();

        let cursor_pos = self.cursor as usize;
        let result = NewlineHandler::insert_newline(&self.text, cursor_pos);

        match result {
            Ok((new_text, new_cursor)) => {
                self.text = new_text;
                self.cursor = new_cursor;
                self.selection = None;
                Ok(())
            }
            Err(e) => {
                // Restore state on error
                self.undo();
                Err(e)
            }
        }
    }

    /// Save the current state to the undo stack
    fn save_state(&mut self) {
        let state = EditorState::new(self.text.clone(), self.cursor, self.selection);
        self.undo_stack.push(state);
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
                        // For inline operations without selection, find word boundaries
                        Ok(CursorUtils::find_word_boundaries(&self.text, cursor_pos))
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
    fn test_render_basic() {
        let editor = MarkdownEditor::new("**bold** text".to_string());
        let spans = editor.render();
        assert!(!spans.is_empty());
    }
}
