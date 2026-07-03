use super::{MarkdownError, Operation, Result};

/// Result type for operation functions that return new text, cursor position, and optional selection
type OperationResult = Result<(String, u32, Option<(u32, u32)>)>;

/// Operations for creating and manipulating lists
pub struct ListOperations;

impl ListOperations {
    /// Create a list from the selected lines
    pub fn create_list(text: &str, start: usize, end: usize, operation: Operation) -> OperationResult {
        if start > end || end > text.len() {
            return Err(MarkdownError::InvalidSelection("Invalid range".to_string()));
        }

        let is_ordered = matches!(operation, Operation::CreateOrderedList);

        // Find all lines in the selection
        let lines = Self::get_lines_in_range(text, start, end);

        let mut new_text = String::new();
        let mut offset = 0i32;
        let mut item_number = 1;

        for (line_idx, (line_start, line_end)) in lines.iter().enumerate() {
            // Add text before this line (if first line)
            if line_idx == 0 {
                new_text.push_str(&text[..*line_start]);
            }

            let line_content = &text[*line_start..*line_end];

            // Check if line is already a list item
            let existing_list = Self::parse_list_item(line_content);

            if let Some((_existing_level, _existing_ordered, _)) = existing_list {
                // Already a list, toggle it off
                let prefix_len = Self::get_list_prefix_len(line_content);
                new_text.push_str(&line_content[prefix_len..]);
                offset -= prefix_len as i32;
            } else {
                // Not a list, make it one
                let prefix = if is_ordered {
                    format!("{}. ", item_number)
                } else {
                    "- ".to_string()
                };

                new_text.push_str(&prefix);
                new_text.push_str(line_content);
                offset += prefix.len() as i32;
                item_number += 1;
            }

            let line_separator = Self::line_separator_after(text, *line_end);

            // Add newline if not last line
            if line_idx < lines.len() - 1 {
                new_text.push_str(line_separator);
            } else if *line_end < text.len() {
                // Add remaining text after last line
                new_text.push_str(&text[*line_end..]);
            }
        }

        let new_cursor = (end as i32 + offset).max(0) as u32;
        Ok((new_text, new_cursor, None))
    }

    /// Indent the list item(s) in the selection.
    ///
    /// CommonMark treats 4+ leading spaces as a code block *unless* the line nests under a
    /// preceding list item — nesting is resolved relative to that item's content column, so
    /// depth is otherwise unbounded. A line with nothing valid to nest under (e.g. the first
    /// item in a list) has no safe target, so indenting it is a no-op rather than risking a
    /// code block.
    pub fn indent_list(text: &str, start: usize, end: usize) -> OperationResult {
        let lines = Self::get_lines_in_range(text, start, end);

        let mut new_text = String::new();
        let mut total_offset = 0i32;
        let mut prev_line: Option<String> = None;

        for (line_idx, (line_start, line_end)) in lines.iter().enumerate() {
            if line_idx == 0 {
                new_text.push_str(&text[..*line_start]);
                prev_line = Self::line_before(text, *line_start).map(str::to_string);
            }

            let line_content = &text[*line_start..*line_end];

            let new_line = match Self::parse_list_item(line_content) {
                Some((current_spaces, _, current_content_start)) => {
                    let is_empty_item = line_content[current_content_start..].trim().is_empty();
                    match prev_line.as_deref().and_then(Self::parse_list_item) {
                        // The previous item is at the same or deeper level, so it's a valid
                        // parent: nest this line at its content column. But an empty item
                        // nested directly under another line's content is indistinguishable
                        // from a Setext heading underline (e.g. "  - "), and CommonMark
                        // resolves that ambiguity in favor of the heading, collapsing the
                        // list. Skip nesting rather than corrupt the document.
                        Some((prev_spaces, _, prev_content_start))
                            if prev_spaces as usize >= current_spaces as usize && !is_empty_item =>
                        {
                            total_offset += prev_content_start as i32 - current_spaces as i32;
                            format!(
                                "{}{}",
                                " ".repeat(prev_content_start),
                                &line_content[current_spaces as usize..]
                            )
                        }
                        // No valid parent above this line, or nesting would create an
                        // ambiguous empty item; indenting further isn't safe.
                        _ => line_content.to_string(),
                    }
                }
                None => line_content.to_string(),
            };

            new_text.push_str(&new_line);
            prev_line = Some(new_line);

            let line_separator = Self::line_separator_after(text, *line_end);

            if line_idx < lines.len() - 1 {
                new_text.push_str(line_separator);
            } else if *line_end < text.len() {
                new_text.push_str(&text[*line_end..]);
            }
        }

        let new_cursor = (end as i32 + total_offset).max(0) as u32;
        Ok((new_text, new_cursor, None))
    }

    /// Unindent the list item(s) in the selection.
    ///
    /// Mirrors `indent_list`: de-nests down to the level of the nearest preceding list item
    /// that's shallower than this one (becoming its sibling), or to the top level if there's
    /// no such item.
    pub fn unindent_list(text: &str, start: usize, end: usize) -> OperationResult {
        let lines = Self::get_lines_in_range(text, start, end);

        let mut new_text = String::new();
        let mut total_offset = 0i32;
        let mut prev_line: Option<String> = None;

        for (line_idx, (line_start, line_end)) in lines.iter().enumerate() {
            if line_idx == 0 {
                new_text.push_str(&text[..*line_start]);
                prev_line = Self::line_before(text, *line_start).map(str::to_string);
            }

            let line_content = &text[*line_start..*line_end];

            let new_line = match Self::parse_list_item(line_content) {
                Some((current_spaces, _, _)) if current_spaces > 0 => {
                    let target = match prev_line.as_deref().and_then(Self::parse_list_item) {
                        Some((prev_spaces, _, _)) if (prev_spaces as usize) < (current_spaces as usize) => {
                            prev_spaces as usize
                        }
                        _ => 0,
                    };
                    total_offset -= current_spaces as i32 - target as i32;
                    format!("{}{}", " ".repeat(target), &line_content[current_spaces as usize..])
                }
                _ => line_content.to_string(),
            };

            new_text.push_str(&new_line);
            prev_line = Some(new_line);

            let line_separator = Self::line_separator_after(text, *line_end);

            if line_idx < lines.len() - 1 {
                new_text.push_str(line_separator);
            } else if *line_end < text.len() {
                new_text.push_str(&text[*line_end..]);
            }
        }

        let new_cursor = (end as i32 + total_offset).max(0) as u32;
        Ok((new_text, new_cursor, None))
    }

    /// Returns the content of the line immediately preceding the line starting at `line_start`,
    /// or `None` if `line_start` is at the beginning of the text.
    fn line_before(text: &str, line_start: usize) -> Option<&str> {
        if line_start == 0 {
            return None;
        }

        let before = &text[..line_start];
        let before = before.strip_suffix("\r\n").or_else(|| before.strip_suffix('\n'))?;
        let prev_start = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
        Some(&before[prev_start..])
    }

    /// Get all lines (as byte ranges) that intersect with the given range
    fn get_lines_in_range(text: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
        let mut lines = Vec::new();
        let mut current_start = 0;

        for line in text.lines() {
            let line_end = current_start + line.len();

            // Check if this line intersects with the range
            if line_end >= start && current_start <= end {
                lines.push((current_start, line_end));
            }

            // Move to next line, accounting for LF and CRLF separators.
            current_start = line_end + Self::line_separator_after(text, line_end).len();

            // Stop if we're past the end
            if current_start > end {
                break;
            }
        }

        // Handle text that doesn't end with newline
        if current_start < text.len() && current_start <= end {
            lines.push((current_start, text.len()));
        }

        // Handle cursor positioned at text.len() after a trailing newline: Rust's
        // .lines() does not yield the virtual empty line, so nothing is pushed above.
        if lines.is_empty() && start <= text.len() {
            lines.push((start, end.min(text.len())));
        }

        lines
    }

    fn line_separator_after(text: &str, line_end: usize) -> &str {
        if text.as_bytes().get(line_end) == Some(&b'\r') && text.as_bytes().get(line_end + 1) == Some(&b'\n') {
            "\r\n"
        } else if text.as_bytes().get(line_end) == Some(&b'\n') {
            "\n"
        } else {
            ""
        }
    }

    /// Parse a list item and return (leading_spaces, is_ordered, content_start)
    fn parse_list_item(line: &str) -> Option<(u8, bool, usize)> {
        super::list_parsing::parse_list_item(line)
    }

    /// Get the length of the list prefix (indentation + marker + space)
    fn get_list_prefix_len(line: &str) -> usize {
        Self::parse_list_item(line).map(|(_, _, s)| s).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_unordered_list() {
        let text = "line 1\nline 2\nline 3";
        let (new_text, _, _) =
            ListOperations::create_list(text, 0, text.len(), Operation::CreateUnorderedList).unwrap();

        assert_eq!(new_text, "- line 1\n- line 2\n- line 3");
    }

    #[test]
    fn test_create_ordered_list() {
        let text = "line 1\nline 2\nline 3";
        let (new_text, _, _) = ListOperations::create_list(text, 0, text.len(), Operation::CreateOrderedList).unwrap();

        assert_eq!(new_text, "1. line 1\n2. line 2\n3. line 3");
    }

    #[test]
    fn test_create_ordered_list_preserves_crlf_line_ranges() {
        let text = "line 1\r\nline 2\r\nline 3";
        let (new_text, _, _) = ListOperations::create_list(text, 0, text.len(), Operation::CreateOrderedList).unwrap();

        assert_eq!(new_text, "1. line 1\r\n2. line 2\r\n3. line 3");
    }

    #[test]
    fn test_toggle_list_off() {
        let text = "- item 1\n- item 2";
        let (new_text, _, _) =
            ListOperations::create_list(text, 0, text.len(), Operation::CreateUnorderedList).unwrap();

        assert_eq!(new_text, "item 1\nitem 2");
    }

    #[test]
    fn test_indent_list() {
        // item 1 has nothing to nest under, so it stays put; item 2 nests under item 1.
        let text = "- item 1\n- item 2";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();

        assert_eq!(new_text, "- item 1\n  - item 2");
    }

    #[test]
    fn test_indent_list_preserves_crlf_line_ranges() {
        let text = "- item 1\r\n- item 2";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();

        assert_eq!(new_text, "- item 1\r\n  - item 2");
    }

    #[test]
    fn test_unindent_list() {
        let text = "- item 1\n  - item 2";
        let (new_text, _, _) = ListOperations::unindent_list(text, 0, text.len()).unwrap();

        assert_eq!(new_text, "- item 1\n- item 2");
    }

    #[test]
    fn test_indent_non_list() {
        let text = "regular text";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();

        // Should not change non-list text
        assert_eq!(new_text, text);
    }

    // parse_list_item is tested directly in list_parsing.rs, which owns the implementation.

    #[test]
    fn test_empty_ordered_marker_can_be_wrapped_as_list_content() {
        let text = ". item";
        let (new_text, _, _) = ListOperations::create_list(text, 0, text.len(), Operation::CreateOrderedList).unwrap();

        assert_eq!(new_text, "1. . item");
    }

    #[test]
    fn test_indent_empty_item_is_noop() {
        // Nesting an empty item directly under item 1's content would produce "  - ", which
        // is ambiguous with a Setext heading underline: CommonMark can't let an empty list
        // item interrupt the preceding paragraph, so it parses "item 1" as a heading instead
        // of a list item. Skip the nest to avoid corrupting the document.
        let text = "- item 1\n- ";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();
        assert_eq!(new_text, text);
    }

    #[test]
    fn test_indent_empty_item_under_nested_parent_is_noop() {
        // Same ambiguity, one level deeper: nesting the empty item under "item1a" would
        // produce "    - ", turning "item1a" into a heading.
        let text = "- item1\n  - item1a\n  - ";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();
        assert_eq!(new_text, text);
    }

    #[test]
    fn test_indent_solitary_item_is_noop() {
        // No preceding item to nest under, so indenting is a no-op. This is exactly the
        // scenario that used to turn into a CommonMark code block before this guard existed.
        let text = "- item 1";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();
        assert_eq!(new_text, text);
    }

    #[test]
    fn test_indent_first_item_of_list_is_noop() {
        let text = "- item 1\n- item 2\n- item 3";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, 0).unwrap();
        assert_eq!(new_text, text);
    }

    #[test]
    fn test_nested_list_operations() {
        // Building a 3-level hierarchy requires cascading indents: an item can only nest
        // under a preceding sibling that is already at an equal or deeper level.
        let text = "- item 1\n- item 2\n- item 3".to_string();

        // Nest item 2 under item 1.
        let item2_pos = text.find("- item 2").unwrap();
        let (text, _, _) = ListOperations::indent_list(&text, item2_pos, item2_pos).unwrap();
        assert_eq!(text, "- item 1\n  - item 2\n- item 3");

        // Nest item 3 under item 2 (now deeper than item 1).
        let item3_pos = text.find("- item 3").unwrap();
        let (text, _, _) = ListOperations::indent_list(&text, item3_pos, item3_pos).unwrap();
        assert_eq!(text, "- item 1\n  - item 2\n    - item 3");

        // Unindent item 3 back down to item 2's level.
        let item3_pos = text.find("- item 3").unwrap();
        let (text, _, _) = ListOperations::unindent_list(&text, item3_pos, item3_pos).unwrap();
        assert_eq!(text, "- item 1\n  - item 2\n  - item 3");
    }

    #[test]
    fn test_indent_list_at_end_after_trailing_newline_does_not_clear_text() {
        // Cursor at text.len() after a trailing \n: Rust's .lines() does not yield the
        // virtual empty line, so get_lines_in_range returned [], causing the whole
        // document to be replaced with "".
        let text = "**bold text**\n\n";
        let end = text.len(); // cursor at end
        let (new_text, _, _) = ListOperations::indent_list(text, end, end).unwrap();
        assert_eq!(new_text, text);
    }

    #[test]
    fn test_unindent_list_at_end_after_trailing_newline_does_not_clear_text() {
        let text = "**bold text**\n\n";
        let end = text.len();
        let (new_text, _, _) = ListOperations::unindent_list(text, end, end).unwrap();
        assert_eq!(new_text, text);
    }

    #[test]
    fn test_create_list_at_end_after_trailing_newline_does_not_clear_text() {
        // create_list on the empty trailing line adds a list marker; the important
        // thing is that existing text is NOT destroyed.
        let text = "**bold text**\n\n";
        let end = text.len();
        let (new_text, _, _) = ListOperations::create_list(text, end, end, Operation::CreateUnorderedList).unwrap();
        assert!(
            new_text.contains("**bold text**"),
            "existing text must survive: got {new_text:?}"
        );
    }
}
