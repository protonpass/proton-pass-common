use unicode_segmentation::UnicodeSegmentation;

/// Utilities for handling cursor positions and selections with Unicode awareness
pub struct CursorUtils;

impl CursorUtils {
    /// Find word boundaries around a cursor position
    /// Returns (start, end) of the word containing the cursor
    /// If cursor is at a word boundary (space/punctuation), looks backward for the previous word
    pub fn find_word_boundaries(text: &str, cursor: usize) -> (usize, usize) {
        if text.is_empty() || cursor > text.len() {
            return (cursor, cursor);
        }

        // Handle cursor at the very end
        if cursor >= text.len() {
            return Self::find_word_boundaries_backward(text, cursor);
        }

        let graphemes: Vec<&str> = text.graphemes(true).collect();
        let mut byte_positions: Vec<usize> = Vec::new();
        let mut current_byte = 0;

        for grapheme in &graphemes {
            byte_positions.push(current_byte);
            current_byte += grapheme.len();
        }
        byte_positions.push(current_byte); // Add final position

        // Find which grapheme comes AFTER the cursor
        let grapheme_after_cursor = byte_positions
            .iter()
            .position(|&pos| pos > cursor)
            .unwrap_or(graphemes.len());

        // Check what's to the LEFT of cursor (the character before cursor position)
        let grapheme_before_cursor = if grapheme_after_cursor > 0 {
            grapheme_after_cursor - 1
        } else {
            return (cursor, cursor);
        };

        // If cursor is right after a word boundary (space/punctuation), look backward for the previous word
        if grapheme_before_cursor < graphemes.len() && Self::is_word_boundary(graphemes[grapheme_before_cursor]) {
            // Look backward to find the previous word
            if grapheme_before_cursor > 0 && !Self::is_word_boundary(graphemes[grapheme_before_cursor - 1]) {
                return Self::find_word_boundaries_backward(text, cursor);
            }
            return (cursor, cursor);
        }

        // We're in the middle of a word, use the grapheme before cursor for word detection
        let cursor_grapheme_idx = grapheme_before_cursor;

        // Find start of word
        let mut start_idx = cursor_grapheme_idx;
        while start_idx > 0 && !Self::is_word_boundary(graphemes[start_idx - 1]) {
            start_idx -= 1;
        }

        // Find end of word
        let mut end_idx = cursor_grapheme_idx;
        while end_idx < graphemes.len() && !Self::is_word_boundary(graphemes[end_idx]) {
            end_idx += 1;
        }

        let start = byte_positions[start_idx];
        let end = byte_positions[end_idx];

        (start, end)
    }

    fn find_word_boundaries_backward(text: &str, cursor: usize) -> (usize, usize) {
        let graphemes: Vec<&str> = text.graphemes(true).collect();
        if graphemes.is_empty() {
            return (cursor, cursor);
        }

        let mut byte_positions: Vec<usize> = Vec::new();
        let mut current_byte = 0;

        for grapheme in &graphemes {
            byte_positions.push(current_byte);
            current_byte += grapheme.len();
        }
        byte_positions.push(current_byte); // Add final position

        // Find which grapheme the cursor is at or before
        let mut cursor_idx = byte_positions
            .iter()
            .position(|&pos| pos >= cursor)
            .unwrap_or(graphemes.len());

        // If we're exactly at a position, move back one to get the grapheme before cursor
        if cursor_idx < byte_positions.len() && byte_positions[cursor_idx] == cursor && cursor_idx > 0 {
            cursor_idx -= 1;
        }

        // Skip backward over any word boundaries (spaces/punctuation)
        while cursor_idx > 0 && Self::is_word_boundary(graphemes[cursor_idx]) {
            cursor_idx -= 1;
        }

        if cursor_idx >= graphemes.len() || Self::is_word_boundary(graphemes[cursor_idx]) {
            return (cursor, cursor);
        }

        // Now we're at a non-boundary character, find the start and end of this word
        let end_idx = cursor_idx + 1; // End is after this character

        // Find start of word
        while cursor_idx > 0 && !Self::is_word_boundary(graphemes[cursor_idx - 1]) {
            cursor_idx -= 1;
        }

        (
            byte_positions[cursor_idx],
            byte_positions.get(end_idx).copied().unwrap_or(cursor),
        )
    }

    /// Check if a grapheme is a word boundary (whitespace or punctuation)
    fn is_word_boundary(grapheme: &str) -> bool {
        grapheme
            .chars()
            .all(|c| c.is_whitespace() || c.is_ascii_punctuation() && c != '_')
    }

    /// Validate that a byte position is at a valid UTF-8 character boundary
    pub fn is_char_boundary(text: &str, pos: usize) -> bool {
        text.is_char_boundary(pos)
    }

    /// Get the number of grapheme clusters in text
    #[allow(dead_code)]
    pub fn grapheme_count(text: &str) -> usize {
        text.graphemes(true).count()
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
    fn test_find_word_boundaries_middle() {
        let text = "hello world";
        let (start, end) = CursorUtils::find_word_boundaries(text, 3); // In "hello"
        assert_eq!(&text[start..end], "hello");
    }

    #[test]
    fn test_find_word_boundaries_emoji() {
        let text = "hello 👨‍👩‍👧‍👦 world";
        let emoji_start = "hello ".len();
        // Find boundaries at emoji start (not middle)
        let (start, end) = CursorUtils::find_word_boundaries(text, emoji_start);
        assert_eq!(&text[start..end], "👨‍👩‍👧‍👦");
    }

    #[test]
    fn test_find_word_boundaries_emoji_with_skin_tone() {
        let text = "test 👋🏽 word";
        let emoji_pos = "test ".len();
        // Find boundaries at emoji start (not middle)
        let (start, end) = CursorUtils::find_word_boundaries(text, emoji_pos);
        assert_eq!(&text[start..end], "👋🏽");
    }

    #[test]
    fn test_find_word_boundaries_at_space_after_word() {
        let text = "hello world";
        // Cursor at position 5 (space after "hello") should select "hello"
        let (start, end) = CursorUtils::find_word_boundaries(text, 5);
        assert_eq!(&text[start..end], "hello");
    }

    #[test]
    fn test_find_word_boundaries_at_start_of_word() {
        let text = "  hello  ";
        // Cursor at position 2 (right before 'h' in "hello") should select "hello"
        // This is the START of the word, which should also be detected
        let (start, end) = CursorUtils::find_word_boundaries(text, 2);
        assert_eq!(&text[start..end], "hello");
    }

    #[test]
    fn test_find_word_boundaries_in_leading_spaces() {
        let text = "  hello  ";
        // Cursor at position 1 (in the leading spaces) should return empty
        let (start, end) = CursorUtils::find_word_boundaries(text, 1);
        assert_eq!(start, end);
    }

    #[test]
    fn test_find_word_boundaries_end_of_word() {
        let text = "hello world";
        // Cursor at position 5 (right after "hello") should select "hello"
        let (start, end) = CursorUtils::find_word_boundaries(text, 5);
        assert_eq!(&text[start..end], "hello");
        assert_eq!(start, 0);
        assert_eq!(end, 5);
    }

    #[test]
    fn test_find_word_boundaries_end_of_second_word() {
        let text = "hello world";
        // Cursor at position 11 (right after "world") should select "world"
        let (start, end) = CursorUtils::find_word_boundaries(text, 11);
        assert_eq!(&text[start..end], "world");
        assert_eq!(start, 6);
        assert_eq!(end, 11);
    }

    #[test]
    fn test_find_word_boundaries_end_of_text() {
        let text = "hello";
        // Cursor at position 5 (end of text) should select "hello"
        let (start, end) = CursorUtils::find_word_boundaries(text, 5);
        assert_eq!(&text[start..end], "hello");
    }

    #[test]
    fn test_find_word_boundaries_after_punctuation() {
        let text = "hello, world";
        // Cursor at position 6 (after comma+space) should return empty or select "world"
        let (start, end) = CursorUtils::find_word_boundaries(text, 6);
        // Should return empty at space
        assert_eq!(start, end);
    }

    #[test]
    fn test_find_word_boundaries_end_of_word_with_emoji() {
        let text = "test👋 word";
        // Find the byte position right after the emoji
        let emoji_end = "test👋".len();
        let (start, end) = CursorUtils::find_word_boundaries(text, emoji_end);
        // Should select "test👋"
        assert_eq!(&text[start..end], "test👋");
    }

    #[test]
    fn test_find_line_boundaries() {
        let text = "line1\nline2\nline3";
        let (start, end) = CursorUtils::find_line_boundaries(text, 8); // In "line2"
        assert_eq!(&text[start..end], "line2");
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

    #[test]
    fn test_grapheme_count() {
        assert_eq!(CursorUtils::grapheme_count("hello"), 5);
        assert_eq!(CursorUtils::grapheme_count("👨‍👩‍👧‍👦"), 1);
        assert_eq!(CursorUtils::grapheme_count("hello 👋🏽"), 7);
    }
}
