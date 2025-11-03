/// Represents a snapshot of the editor state for undo/redo
#[derive(Debug, Clone, PartialEq)]
pub struct EditorState {
    pub text: String,
    pub cursor: u32,
    pub selection: Option<(u32, u32)>,
}

impl EditorState {
    pub fn new(text: String, cursor: u32, selection: Option<(u32, u32)>) -> Self {
        Self {
            text,
            cursor,
            selection,
        }
    }
}

/// Manages undo/redo functionality
#[derive(Debug, Clone)]
pub struct UndoStack {
    undo_stack: Vec<EditorState>,
    redo_stack: Vec<EditorState>,
    max_size: usize,
}

impl UndoStack {
    pub fn new(max_size: usize) -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            max_size,
        }
    }

    /// Push a new state onto the undo stack
    pub fn push(&mut self, state: EditorState) {
        // Clear redo stack when new action is performed
        self.redo_stack.clear();

        // Add to undo stack
        self.undo_stack.push(state);

        // Limit stack size
        if self.undo_stack.len() > self.max_size {
            self.undo_stack.remove(0);
        }
    }

    /// Pop from undo stack and push current state to redo
    pub fn undo(&mut self, current_state: EditorState) -> Option<EditorState> {
        if let Some(prev_state) = self.undo_stack.pop() {
            self.redo_stack.push(current_state);
            Some(prev_state)
        } else {
            None
        }
    }

    /// Pop from redo stack and push current state to undo
    pub fn redo(&mut self, current_state: EditorState) -> Option<EditorState> {
        if let Some(next_state) = self.redo_stack.pop() {
            self.undo_stack.push(current_state);
            Some(next_state)
        } else {
            None
        }
    }

    /// Check if undo is available
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Check if redo is available
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Clear all undo/redo history
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_undo_stack_basic() {
        let mut stack = UndoStack::new(10);

        let state1 = EditorState::new("hello".to_string(), 5, None);
        let state2 = EditorState::new("hello world".to_string(), 11, None);

        stack.push(state1.clone());

        // Undo should return state1
        let undone = stack.undo(state2.clone());
        assert_eq!(undone, Some(state1.clone()));

        // Redo should return state2
        let redone = stack.redo(state1);
        assert_eq!(redone, Some(state2));
    }

    #[test]
    fn test_undo_clears_redo() {
        let mut stack = UndoStack::new(10);

        let state1 = EditorState::new("a".to_string(), 1, None);
        let state2 = EditorState::new("ab".to_string(), 2, None);
        let state3 = EditorState::new("abc".to_string(), 3, None);

        stack.push(state1.clone());
        stack.undo(state2.clone());

        assert!(stack.can_redo());

        // New action should clear redo stack
        stack.push(state3);
        assert!(!stack.can_redo());
    }

    #[test]
    fn test_max_size() {
        let mut stack = UndoStack::new(3);

        for i in 0..5 {
            stack.push(EditorState::new(i.to_string(), i as u32, None));
        }

        // Should only keep last 3
        assert_eq!(stack.undo_stack.len(), 3);
        assert_eq!(stack.undo_stack[0].text, "2");
        assert_eq!(stack.undo_stack[2].text, "4");
    }
}
