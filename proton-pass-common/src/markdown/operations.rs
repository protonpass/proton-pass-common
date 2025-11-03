use super::{MarkdownError, Operation, Result};

/// Result type for operation functions that return new text, cursor position, and optional selection
type OperationResult = Result<(String, u32, Option<(u32, u32)>)>;

/// Operations for applying inline markdown formatting
pub struct MarkdownOperations;

impl MarkdownOperations {
    /// Apply inline formatting (bold, italic, strikethrough, header, blockquote) to a text range
    pub fn apply_inline_formatting(text: &str, start: usize, end: usize, operation: Operation) -> OperationResult {
        if start > end || end > text.len() {
            return Err(MarkdownError::InvalidSelection("Invalid range".to_string()));
        }

        // If range is empty (cursor only), return unchanged
        if start == end {
            return Ok((text.to_string(), start as u32, None));
        }

        match operation {
            Operation::Bold => Self::toggle_wrapper(text, start, end, "**"),
            Operation::Italic => Self::toggle_wrapper(text, start, end, "*"),
            Operation::Strikethrough => Self::toggle_wrapper(text, start, end, "~~"),
            Operation::Header(level) => {
                if !(1..=6).contains(&level) {
                    return Err(MarkdownError::InvalidHeaderLevel(format!(
                        "Header level must be 1-6, got {}",
                        level
                    )));
                }
                Self::apply_header(text, start, end, level)
            }
            Operation::Blockquote => Self::apply_blockquote(text, start, end),
            _ => Err(MarkdownError::InvalidOperation(
                "Not an inline formatting operation".to_string(),
            )),
        }
    }

    /// Toggle a wrapper (like ** for bold) around the selected text
    fn toggle_wrapper(text: &str, start: usize, end: usize, wrapper: &str) -> OperationResult {
        let wrapper_len = wrapper.len();
        let selected_text = &text[start..end];

        // Special case: Handle *** (bold+italic combined)
        // Search for *** even if there are other wrappers in between
        if wrapper == "*" || wrapper == "**" {
            if let Some(triple_star_pos) = Self::find_triple_star_positions(text, start, end) {
                let (opening_pos, closing_pos) = triple_star_pos;
                if wrapper == "*" {
                    // Remove one * from *** to leave **
                    let mut new_text = String::new();
                    new_text.push_str(&text[..opening_pos]);
                    new_text.push_str("**");
                    new_text.push_str(&text[opening_pos + 3..closing_pos]);
                    new_text.push_str("**");
                    new_text.push_str(&text[closing_pos + 3..]);

                    let new_cursor = (closing_pos - 1) as u32;
                    return Ok((new_text, new_cursor, None));
                } else {
                    // Remove two * from *** to leave *
                    let mut new_text = String::new();
                    new_text.push_str(&text[..opening_pos]);
                    new_text.push('*');
                    new_text.push_str(&text[opening_pos + 3..closing_pos]);
                    new_text.push('*');
                    new_text.push_str(&text[closing_pos + 3..]);

                    let new_cursor = (closing_pos - 2) as u32;
                    return Ok((new_text, new_cursor, None));
                }
            }
        }

        // Search for the wrapper, potentially nested within other markdown syntax
        // We need to find matching wrappers that aren't immediately adjacent
        let wrapper_positions = Self::find_wrapper_positions(text, start, end, wrapper);

        if let Some((wrapper_start, wrapper_end)) = wrapper_positions {
            // Remove the wrapper
            let mut new_text = String::new();
            new_text.push_str(&text[..wrapper_start]);
            new_text.push_str(&text[wrapper_start + wrapper_len..wrapper_end]);
            new_text.push_str(&text[wrapper_end + wrapper_len..]);

            let new_cursor = wrapper_end as u32 - wrapper_len as u32;
            // Clear selection after unwrapping
            let new_selection = None;

            Ok((new_text, new_cursor, new_selection))
        } else {
            // Add the wrapper
            let mut new_text = String::new();
            new_text.push_str(&text[..start]);
            new_text.push_str(wrapper);
            new_text.push_str(selected_text);
            new_text.push_str(wrapper);
            new_text.push_str(&text[end..]);

            let new_cursor = (end + wrapper_len) as u32;
            // Clear selection after wrapping - cursor positioned inside markers for continued typing
            let new_selection = None;

            Ok((new_text, new_cursor, new_selection))
        }
    }

    /// Find wrapper positions around a selection, searching through nested markdown
    /// Returns Some((start_pos, end_pos)) if wrapper is found, where positions point to the start of each wrapper
    fn find_wrapper_positions(text: &str, start: usize, end: usize, wrapper: &str) -> Option<(usize, usize)> {
        let wrapper_len = wrapper.len();

        // Known markdown wrappers to skip over when searching
        let wrappers = ["**", "~~", "*", "`"];

        // Search backwards from start for the opening wrapper
        let mut search_start = start;
        let opening_pos = loop {
            if search_start < wrapper_len {
                break None;
            }

            let check_pos = search_start - wrapper_len;
            if &text[check_pos..search_start] == wrapper {
                // Special case: if looking for "*", make sure it's not part of "**"
                if wrapper == "*" {
                    // Check if there's another * before or after this one
                    let has_star_before = check_pos > 0 && &text[check_pos - 1..check_pos] == "*";
                    let has_star_after = search_start < text.len() && &text[search_start..search_start + 1] == "*";

                    if has_star_before || has_star_after {
                        // This is part of **, not a standalone *, skip over it
                        search_start = check_pos;
                        continue;
                    }
                }
                // Found it!
                break Some(check_pos);
            }

            // Check if we hit another markdown wrapper - skip over it
            let mut found_other = false;
            for other_wrapper in &wrappers {
                if *other_wrapper != wrapper && search_start >= other_wrapper.len() {
                    let other_check_pos = search_start - other_wrapper.len();
                    if &text[other_check_pos..search_start] == *other_wrapper {
                        search_start = other_check_pos;
                        found_other = true;
                        break;
                    }
                }
            }

            if !found_other {
                // Not a markdown wrapper, give up
                break None;
            }
        };

        let opening_pos = opening_pos?;

        // Search forwards from end for the closing wrapper
        let mut search_end = end;
        let closing_pos = loop {
            if search_end + wrapper_len > text.len() {
                break None;
            }

            if &text[search_end..search_end + wrapper_len] == wrapper {
                // Special case: if looking for "*", make sure it's not part of "**"
                if wrapper == "*" {
                    // Check if there's another * before or after this one
                    let has_star_before = search_end > 0 && &text[search_end - 1..search_end] == "*";
                    let has_star_after = search_end + 1 < text.len() && &text[search_end + 1..search_end + 2] == "*";

                    if has_star_before || has_star_after {
                        // This is part of **, not a standalone *, skip over it
                        search_end += wrapper_len;
                        continue;
                    }
                }
                // Found it!
                break Some(search_end);
            }

            // Check if we hit another markdown wrapper - skip over it
            let mut found_other = false;
            for other_wrapper in &wrappers {
                if *other_wrapper != wrapper && search_end + other_wrapper.len() <= text.len()
                    && &text[search_end..search_end + other_wrapper.len()] == *other_wrapper {
                        search_end += other_wrapper.len();
                        found_other = true;
                        break;
                    }
            }

            if !found_other {
                // Not a markdown wrapper, give up
                break None;
            }
        };

        let closing_pos = closing_pos?;

        Some((opening_pos, closing_pos))
    }

    /// Find *** (bold+italic) positions, searching through other markdown wrappers
    fn find_triple_star_positions(text: &str, start: usize, end: usize) -> Option<(usize, usize)> {
        // Known markdown wrappers to skip over when searching
        let wrappers = ["**", "~~", "`"];

        // Search backwards from start for ***
        let mut search_start = start;
        let opening_pos = loop {
            if search_start < 3 {
                break None;
            }

            let check_pos = search_start - 3;
            if &text[check_pos..search_start] == "***" {
                // Found it!
                break Some(check_pos);
            }

            // Check if we hit another markdown wrapper - skip over it
            let mut found_other = false;
            for other_wrapper in &wrappers {
                if search_start >= other_wrapper.len() {
                    let other_check_pos = search_start - other_wrapper.len();
                    if &text[other_check_pos..search_start] == *other_wrapper {
                        search_start = other_check_pos;
                        found_other = true;
                        break;
                    }
                }
            }

            if !found_other {
                // Not a markdown wrapper, give up
                break None;
            }
        };

        let opening_pos = opening_pos?;

        // Search forwards from end for ***
        let mut search_end = end;
        let closing_pos = loop {
            if search_end + 3 > text.len() {
                break None;
            }

            if &text[search_end..search_end + 3] == "***" {
                // Found it!
                break Some(search_end);
            }

            // Check if we hit another markdown wrapper - skip over it
            let mut found_other = false;
            for other_wrapper in &wrappers {
                if search_end + other_wrapper.len() <= text.len()
                    && &text[search_end..search_end + other_wrapper.len()] == *other_wrapper {
                        search_end += other_wrapper.len();
                        found_other = true;
                        break;
                    }
            }

            if !found_other {
                // Not a markdown wrapper, give up
                break None;
            }
        };

        let closing_pos = closing_pos?;

        Some((opening_pos, closing_pos))
    }

    /// Apply or toggle a header to the line(s) containing the selection
    fn apply_header(text: &str, start: usize, _end: usize, level: u8) -> OperationResult {
        // Find the start of the line
        let line_start = text[..start].rfind('\n').map(|p| p + 1).unwrap_or(0);

        // Check if line already has a header
        let line_prefix = &text[line_start..];
        let header_prefix = "#".repeat(level as usize) + " ";

        let existing_header = Self::get_existing_header(line_prefix);

        let mut new_text = String::new();
        new_text.push_str(&text[..line_start]);

        if let Some(existing_level) = existing_header {
            // Remove existing header
            let existing_prefix = "#".repeat(existing_level as usize) + " ";
            let content_start = line_start + existing_prefix.len();

            if existing_level == level {
                // Same level, remove it
                new_text.push_str(&text[content_start..]);
                let offset = -(existing_prefix.len() as i32);
                let new_cursor = (start as i32 + offset).max(line_start as i32) as u32;
                Ok((new_text, new_cursor, None))
            } else {
                // Different level, replace it
                new_text.push_str(&header_prefix);
                new_text.push_str(&text[content_start..]);

                let offset = header_prefix.len() as i32 - existing_prefix.len() as i32;
                let new_cursor = (start as i32 + offset).max(line_start as i32) as u32;
                Ok((new_text, new_cursor, None))
            }
        } else {
            // No existing header, add one
            new_text.push_str(&header_prefix);
            new_text.push_str(&text[line_start..]);

            let new_cursor = (start + header_prefix.len()) as u32;
            Ok((new_text, new_cursor, None))
        }
    }

    /// Check if a line starts with a header and return its level
    fn get_existing_header(line: &str) -> Option<u8> {
        let trimmed = line.trim_start();
        for level in 1..=6 {
            let prefix = "#".repeat(level) + " ";
            if trimmed.starts_with(&prefix) {
                return Some(level as u8);
            }
        }
        None
    }

    /// Apply or toggle blockquote to the line(s) containing the selection
    fn apply_blockquote(text: &str, start: usize, _end: usize) -> OperationResult {
        // Find the start of the line
        let line_start = text[..start].rfind('\n').map(|p| p + 1).unwrap_or(0);

        // Check if line already has blockquote
        let line_prefix = &text[line_start..];
        let blockquote_prefix = "> ";

        let has_blockquote = line_prefix.starts_with(blockquote_prefix);

        let mut new_text = String::new();
        new_text.push_str(&text[..line_start]);

        if has_blockquote {
            // Remove blockquote
            let content_start = line_start + blockquote_prefix.len();
            new_text.push_str(&text[content_start..]);
            let offset = -(blockquote_prefix.len() as i32);
            let new_cursor = (start as i32 + offset).max(line_start as i32) as u32;
            Ok((new_text, new_cursor, None))
        } else {
            // Add blockquote
            new_text.push_str(blockquote_prefix);
            new_text.push_str(&text[line_start..]);

            let new_cursor = (start + blockquote_prefix.len()) as u32;
            Ok((new_text, new_cursor, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_bold() {
        let text = "hello world";
        let (new_text, _cursor, selection) =
            MarkdownOperations::apply_inline_formatting(text, 0, 5, Operation::Bold).unwrap();

        assert_eq!(new_text, "**hello** world");
        // Selection is cleared after formatting
        assert_eq!(selection, None);
    }

    #[test]
    fn test_remove_bold() {
        let text = "**hello** world";
        let (new_text, _cursor, selection) =
            MarkdownOperations::apply_inline_formatting(text, 2, 7, Operation::Bold).unwrap();

        assert_eq!(new_text, "hello world");
        // Selection is cleared after formatting
        assert_eq!(selection, None);
    }

    #[test]
    fn test_apply_italic() {
        let text = "hello world";
        let (new_text, _, _) = MarkdownOperations::apply_inline_formatting(text, 6, 11, Operation::Italic).unwrap();

        assert_eq!(new_text, "hello *world*");
    }

    #[test]
    fn test_apply_strikethrough() {
        let text = "hello world";
        let (new_text, _, _) =
            MarkdownOperations::apply_inline_formatting(text, 0, 5, Operation::Strikethrough).unwrap();

        assert_eq!(new_text, "~~hello~~ world");
    }

    #[test]
    fn test_apply_header() {
        let text = "hello world";
        let (new_text, _, _) = MarkdownOperations::apply_inline_formatting(text, 0, 5, Operation::Header(1)).unwrap();

        assert_eq!(new_text, "# hello world");
    }

    #[test]
    fn test_toggle_header_same_level() {
        let text = "# hello world";
        let (new_text, _, _) = MarkdownOperations::apply_inline_formatting(text, 2, 7, Operation::Header(1)).unwrap();

        assert_eq!(new_text, "hello world");
    }

    #[test]
    fn test_change_header_level() {
        let text = "# hello world";
        let (new_text, _, _) = MarkdownOperations::apply_inline_formatting(text, 2, 7, Operation::Header(2)).unwrap();

        assert_eq!(new_text, "## hello world");
    }

    #[test]
    fn test_header_invalid_level() {
        let text = "hello world";
        let result = MarkdownOperations::apply_inline_formatting(text, 0, 5, Operation::Header(7));

        assert!(result.is_err());
    }

    #[test]
    fn test_empty_selection() {
        let text = "hello world";
        let (new_text, _, _) = MarkdownOperations::apply_inline_formatting(text, 5, 5, Operation::Bold).unwrap();

        assert_eq!(new_text, text);
    }

    #[test]
    fn test_emoji_bold() {
        let text = "hello 👋🏽 world";
        let emoji_start = "hello ".len();
        let emoji_end = emoji_start + "👋🏽".len();

        let (new_text, _, _) =
            MarkdownOperations::apply_inline_formatting(text, emoji_start, emoji_end, Operation::Bold).unwrap();

        assert!(new_text.contains("**👋🏽**"));
    }

    #[test]
    fn test_apply_blockquote() {
        let text = "hello world";
        let (new_text, _, _) = MarkdownOperations::apply_inline_formatting(text, 0, 5, Operation::Blockquote).unwrap();

        assert_eq!(new_text, "> hello world");
    }

    #[test]
    fn test_remove_blockquote() {
        let text = "> hello world";
        let (new_text, _, _) = MarkdownOperations::apply_inline_formatting(text, 2, 7, Operation::Blockquote).unwrap();

        assert_eq!(new_text, "hello world");
    }

    #[test]
    fn test_toggle_blockquote() {
        let text = "line of text";

        // Apply blockquote
        let (new_text, _, _) = MarkdownOperations::apply_inline_formatting(text, 0, 4, Operation::Blockquote).unwrap();
        assert_eq!(new_text, "> line of text");

        // Remove blockquote
        let (final_text, _, _) =
            MarkdownOperations::apply_inline_formatting(&new_text, 2, 6, Operation::Blockquote).unwrap();
        assert_eq!(final_text, "line of text");
    }

    #[test]
    fn test_blockquote_at_start_of_line() {
        let text = "first line\nsecond line";
        let (new_text, _, _) =
            MarkdownOperations::apply_inline_formatting(text, 11, 17, Operation::Blockquote).unwrap();

        assert_eq!(new_text, "first line\n> second line");
    }

    #[test]
    fn test_blockquote_cursor_position() {
        let text = "text";
        let (new_text, cursor, _) =
            MarkdownOperations::apply_inline_formatting(text, 2, 2, Operation::Blockquote).unwrap();

        // Empty selection should return unchanged
        assert_eq!(new_text, "text");
        assert_eq!(cursor, 2);
    }
}
