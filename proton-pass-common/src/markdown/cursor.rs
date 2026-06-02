/// Utilities for handling cursor positions and selections with Unicode awareness
pub struct CursorUtils;

impl CursorUtils {
    /// Find the word containing the cursor only when the cursor is inside it.
    /// Boundaries at the start/end of a word return None so callers can insert
    /// new formatting markers instead of selecting the neighboring word.
    pub fn find_word_containing_cursor(text: &str, cursor: usize) -> Option<(usize, usize)> {
        if text.is_empty() || cursor == 0 || cursor >= text.len() || !text.is_char_boundary(cursor) {
            return None;
        }

        let before = text[..cursor].chars().next_back()?;
        let after = text[cursor..].chars().next()?;
        if !Self::is_word_char(before) || !Self::is_word_char(after) {
            return None;
        }

        let mut start = cursor;
        for (index, ch) in text[..cursor].char_indices().rev() {
            if Self::is_word_char(ch) {
                start = index;
            } else {
                break;
            }
        }

        let mut end = cursor;
        for (offset, ch) in text[cursor..].char_indices() {
            if Self::is_word_char(ch) {
                end = cursor + offset + ch.len_utf8();
            } else {
                break;
            }
        }

        Some((start, end))
    }

    fn is_word_char(ch: char) -> bool {
        ch.is_alphanumeric() || ch == '_'
    }

    /// Validate that a byte position is at a valid UTF-8 character boundary
    #[allow(dead_code)]
    pub fn is_char_boundary(text: &str, pos: usize) -> bool {
        text.is_char_boundary(pos)
    }

    /// Find the line boundaries for a given cursor position
    /// Returns (line_start, line_end) byte positions
    pub fn find_line_boundaries(text: &str, cursor: usize) -> (usize, usize) {
        if text.is_empty() || cursor > text.len() {
            return (cursor, cursor);
        }

        // Find start of line
        let start = text[..cursor].rfind('\n').map(|pos| pos + 1).unwrap_or(0);

        // Find end of line
        let end = text[cursor..].find('\n').map(|pos| cursor + pos).unwrap_or(text.len());

        (start, end)
    }

    /// Check if a selection spans multiple lines
    #[allow(dead_code)]
    pub fn is_multiline_selection(text: &str, start: usize, end: usize) -> bool {
        if start >= end || end > text.len() {
            return false;
        }

        text[start..end].contains('\n')
    }

    /// Normalize a selection to ensure start <= end
    pub fn normalize_selection(start: usize, end: usize) -> (usize, usize) {
        if start <= end {
            (start, end)
        } else {
            (end, start)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_line_boundaries() {
        let text = "line1\nline2\nline3";
        let (start, end) = CursorUtils::find_line_boundaries(text, 8); // In "line2"
        assert_eq!(&text[start..end], "line2");
    }

    #[test]
    fn test_find_word_containing_cursor_only_inside_word() {
        let text = "hello world";

        let (start, end) = CursorUtils::find_word_containing_cursor(text, 8).unwrap();
        assert_eq!(&text[start..end], "world");

        assert_eq!(CursorUtils::find_word_containing_cursor(text, 6), None);
        assert_eq!(CursorUtils::find_word_containing_cursor(text, 11), None);
        assert_eq!(CursorUtils::find_word_containing_cursor(text, 5), None);
    }

    #[test]
    fn test_find_word_containing_cursor_supports_unicode_letters() {
        let text = "Héllo mundo";
        let cursor = "Hé".len();

        let (start, end) = CursorUtils::find_word_containing_cursor(text, cursor).unwrap();

        assert_eq!(&text[start..end], "Héllo");
    }

    #[test]
    fn test_is_multiline_selection() {
        let text = "line1\nline2\nline3";
        assert!(CursorUtils::is_multiline_selection(text, 0, 10));
        assert!(!CursorUtils::is_multiline_selection(text, 0, 5));
    }

    #[test]
    fn test_normalize_selection() {
        assert_eq!(CursorUtils::normalize_selection(5, 10), (5, 10));
        assert_eq!(CursorUtils::normalize_selection(10, 5), (5, 10));
        assert_eq!(CursorUtils::normalize_selection(5, 5), (5, 5));
    }
}
