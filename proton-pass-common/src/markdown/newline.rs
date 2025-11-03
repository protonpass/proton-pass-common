use super::{MarkdownError, Result};

/// Handles smart newline insertion with automatic list continuation
pub struct NewlineHandler;

impl NewlineHandler {
    /// Insert a newline at the cursor position with smart list continuation
    /// Returns (new_text, new_cursor_position)
    pub fn insert_newline(text: &str, cursor: usize) -> Result<(String, u32)> {
        if cursor > text.len() {
            return Err(MarkdownError::InvalidCursorPosition(format!(
                "Cursor position {} is beyond text length {}",
                cursor,
                text.len()
            )));
        }

        // Find the line containing the cursor
        let line_start = text[..cursor].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let line_end = text[cursor..].find('\n').map(|p| cursor + p).unwrap_or(text.len());

        let current_line = &text[line_start..line_end];

        // Calculate where we are relative to the line start
        let cursor_in_line = cursor - line_start;

        // Check if current line is a list item AND cursor is within/after the list marker
        if let Some((level, is_ordered, content_start)) = Self::parse_list_item(current_line) {
            // Only apply list logic if cursor is at or after the list marker
            if cursor_in_line == 0 {
                // Cursor at start of line, just insert regular newline
                let mut new_text = String::new();
                new_text.push_str(&text[..cursor]);
                new_text.push('\n');
                new_text.push_str(&text[cursor..]);

                let new_cursor = (cursor + 1) as u32;
                return Ok((new_text, new_cursor));
            }

            let indent = " ".repeat(level as usize * 2);
            let content_after_marker = &current_line[content_start..];

            // If cursor is on an empty list item (just the marker), exit the list
            if content_after_marker.trim().is_empty() {
                // Keep current line, add blank newline after to exit list
                let mut new_text = String::new();
                new_text.push_str(&text[..line_end]);
                new_text.push('\n');
                new_text.push('\n');
                new_text.push_str(&text[line_end..]);

                let new_cursor = (line_end + 2) as u32;
                return Ok((new_text, new_cursor));
            }

            // Split the line at cursor position
            let before_cursor = &current_line[..cursor_in_line];
            let after_cursor = &current_line[cursor_in_line..];

            // Determine the next marker
            let next_marker = if is_ordered {
                // Extract the current number and increment
                let num_str = current_line[indent.len()..].split('.').next().unwrap_or("1").trim();
                let current_num: u32 = num_str.parse().unwrap_or(1);
                format!("{}. ", current_num + 1)
            } else {
                "- ".to_string()
            };

            // Build the new text
            let mut new_text = String::new();
            new_text.push_str(&text[..line_start]);
            new_text.push_str(before_cursor);
            new_text.push('\n');
            new_text.push_str(&indent);
            new_text.push_str(&next_marker);
            new_text.push_str(after_cursor);
            new_text.push_str(&text[line_end..]);

            let new_cursor = (line_start + before_cursor.len() + 1 + indent.len() + next_marker.len()) as u32;
            Ok((new_text, new_cursor))
        } else {
            // Not in a list, just insert a regular newline
            let mut new_text = String::new();
            new_text.push_str(&text[..cursor]);
            new_text.push('\n');
            new_text.push_str(&text[cursor..]);

            let new_cursor = (cursor + 1) as u32;
            Ok((new_text, new_cursor))
        }
    }

    /// Parse a list item and return (level, is_ordered, content_start_offset)
    /// Level is determined by leading spaces (2 spaces = 1 level)
    fn parse_list_item(line: &str) -> Option<(u8, bool, usize)> {
        let spaces = line.chars().take_while(|c| *c == ' ').count();
        let level = (spaces / 2) as u8;
        let after_spaces = &line[spaces..];

        // Check for unordered list
        if after_spaces.starts_with("- ") || after_spaces.starts_with("* ") {
            return Some((level, false, spaces + 2));
        }

        // Check for ordered list
        if let Some(pos) = after_spaces.find(". ") {
            let num_part = &after_spaces[..pos];
            if num_part.chars().all(|c| c.is_ascii_digit()) {
                return Some((level, true, spaces + pos + 2));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_newline() {
        let text = "hello world";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, 5).unwrap();
        assert_eq!(new_text, "hello\n world");
        assert_eq!(cursor, 6);
    }

    #[test]
    fn test_ordered_list_continuation_at_end() {
        let text = "1. First item";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        assert_eq!(new_text, "1. First item\n2. ");
        // "1. First item" (13) + "\n" (1) + "2. " (3) = 17
        assert_eq!(cursor, 17);
    }

    #[test]
    fn test_unordered_list_continuation_at_end() {
        let text = "- First item";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        assert_eq!(new_text, "- First item\n- ");
        // "- First item" (12) + "\n" (1) + "- " (2) = 15
        assert_eq!(cursor, 15);
    }

    #[test]
    fn test_ordered_list_split_middle() {
        let text = "1. First item";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, 9).unwrap(); // After "First"
        assert_eq!(new_text, "1. First \n2. item");
        // "1. First " (9) + "\n" (1) + "2. " (3) = 13
        assert_eq!(cursor, 13);
    }

    #[test]
    fn test_unordered_list_split_middle() {
        let text = "- First item";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, 8).unwrap(); // After "First"
        assert_eq!(new_text, "- First \n- item");
        // "- First " (8) + "\n" (1) + "- " (2) = 11
        assert_eq!(cursor, 11);
    }

    #[test]
    fn test_empty_list_item_exits_list() {
        let text = "1. Item\n2. ";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        // Keeps the empty marker, adds two newlines to exit list
        assert_eq!(new_text, "1. Item\n2. \n\n");
        assert_eq!(cursor, 13); // After both newlines
    }

    #[test]
    fn test_empty_unordered_item_exits_list() {
        let text = "- Item\n- ";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        // Keeps the empty marker, adds two newlines to exit list
        assert_eq!(new_text, "- Item\n- \n\n");
        assert_eq!(cursor, 11); // After both newlines
    }

    #[test]
    fn test_nested_ordered_list() {
        let text = "  1. Nested item";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        assert_eq!(new_text, "  1. Nested item\n  2. ");
        // "  1. Nested item" (16) + "\n" (1) + "  2. " (5) = 22
        assert_eq!(cursor, 22);
    }

    #[test]
    fn test_nested_unordered_list() {
        let text = "  - Nested item";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        assert_eq!(new_text, "  - Nested item\n  - ");
        // "  - Nested item" (15) + "\n" (1) + "  - " (4) = 20
        assert_eq!(cursor, 20);
    }

    #[test]
    fn test_multiline_list() {
        let text = "1. First\n2. Second";
        let (new_text, _cursor) = NewlineHandler::insert_newline(text, 8).unwrap(); // End of "First"
        assert_eq!(new_text, "1. First\n2. \n2. Second");
    }

    #[test]
    fn test_double_digit_list_number() {
        let text = "10. Tenth item";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        assert_eq!(new_text, "10. Tenth item\n11. ");
        // "10. Tenth item" (14) + "\n" (1) + "11. " (4) = 19
        assert_eq!(cursor, 19);
    }

    #[test]
    fn test_list_with_content_after_marker() {
        let text = "1. Item with text";
        let (new_text, _cursor) = NewlineHandler::insert_newline(text, 3).unwrap(); // Right after "1."
                                                                                    // When splitting at position 3, before_cursor is "1. " and after_cursor is "Item with text"
        assert_eq!(new_text, "1. \n2. Item with text");
    }

    #[test]
    fn test_cursor_at_start_of_list_line() {
        let text = "1. Item";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, 0).unwrap();
        assert_eq!(new_text, "\n1. Item");
        assert_eq!(cursor, 1);
    }

    #[test]
    fn test_non_list_text() {
        let text = "Regular text here";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, 7).unwrap();
        assert_eq!(new_text, "Regular\n text here");
        assert_eq!(cursor, 8);
    }

    #[test]
    fn test_asterisk_list_marker() {
        let text = "* Item with asterisk";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        assert_eq!(new_text, "* Item with asterisk\n- ");
        assert_eq!(cursor, 23); // We normalize to "-"
    }

    #[test]
    fn test_empty_text() {
        let text = "";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, 0).unwrap();
        assert_eq!(new_text, "\n");
        assert_eq!(cursor, 1);
    }

    #[test]
    fn test_cursor_beyond_text() {
        let text = "hello";
        let result = NewlineHandler::insert_newline(text, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_levels_nested() {
        let text = "    - Deep nested";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        assert_eq!(new_text, "    - Deep nested\n    - ");
        // "    - Deep nested" (17) + "\n" (1) + "    - " (6) = 24
        assert_eq!(cursor, 24);
    }

    #[test]
    fn test_list_item_with_only_spaces_after_marker() {
        let text = "1.   ";
        let (new_text, cursor) = NewlineHandler::insert_newline(text, text.len()).unwrap();
        // Should exit list since content is empty (spaces only)
        assert_eq!(new_text, "1.   \n\n");
        assert_eq!(cursor, 7); // After both newlines
    }
}
