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
                new_text.push_str(line_content[prefix_len..].trim_start());
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

    /// Indent the list item(s) in the selection
    pub fn indent_list(text: &str, start: usize, end: usize) -> OperationResult {
        let lines = Self::get_lines_in_range(text, start, end);

        let mut new_text = String::new();
        let mut total_offset = 0i32;

        for (line_idx, (line_start, line_end)) in lines.iter().enumerate() {
            if line_idx == 0 {
                new_text.push_str(&text[..*line_start]);
            }

            let line_content = &text[*line_start..*line_end];

            // Check if line is a list item
            if Self::parse_list_item(line_content).is_some() {
                // It's a list item, indent it
                new_text.push_str("  "); // 2 spaces for indentation
                new_text.push_str(line_content);
                total_offset += 2;
            } else {
                // Not a list item, can't indent
                new_text.push_str(line_content);
            }

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

    /// Unindent the list item(s) in the selection
    pub fn unindent_list(text: &str, start: usize, end: usize) -> OperationResult {
        let lines = Self::get_lines_in_range(text, start, end);

        let mut new_text = String::new();
        let mut total_offset = 0i32;

        for (line_idx, (line_start, line_end)) in lines.iter().enumerate() {
            if line_idx == 0 {
                new_text.push_str(&text[..*line_start]);
            }

            let line_content = &text[*line_start..*line_end];

            // Check if line is a list item with indentation
            if let Some((level, _, _)) = Self::parse_list_item(line_content) {
                if level > 0 {
                    // Has indentation, remove up to 2 spaces
                    let spaces_to_remove = line_content.chars().take_while(|c| *c == ' ').count().min(2);

                    new_text.push_str(&line_content[spaces_to_remove..]);
                    total_offset -= spaces_to_remove as i32;
                } else {
                    // No indentation to remove
                    new_text.push_str(line_content);
                }
            } else {
                // Not a list item
                new_text.push_str(line_content);
            }

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

        // Handle case where text doesn't end with newline
        if current_start < text.len() && current_start <= end {
            lines.push((current_start, text.len()));
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

    /// Parse a list item and return (level, is_ordered, content_start)
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
            if !num_part.is_empty() && num_part.chars().all(|c| c.is_ascii_digit()) {
                return Some((level, true, spaces + pos + 2));
            }
        }

        None
    }

    /// Get the length of the list prefix (indentation + marker + space)
    fn get_list_prefix_len(line: &str) -> usize {
        if let Some((_, _, content_start)) = Self::parse_list_item(line) {
            content_start
        } else {
            0
        }
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
        let text = "- item 1\n- item 2";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();

        assert_eq!(new_text, "  - item 1\n  - item 2");
    }

    #[test]
    fn test_indent_list_preserves_crlf_line_ranges() {
        let text = "- item 1\r\n- item 2";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();

        assert_eq!(new_text, "  - item 1\r\n  - item 2");
    }

    #[test]
    fn test_unindent_list() {
        let text = "  - item 1\n  - item 2";
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

    #[test]
    fn test_parse_list_item_unordered() {
        let line = "- item";
        let result = ListOperations::parse_list_item(line);
        assert_eq!(result, Some((0, false, 2)));
    }

    #[test]
    fn test_parse_list_item_ordered() {
        let line = "1. item";
        let result = ListOperations::parse_list_item(line);
        assert_eq!(result, Some((0, true, 3)));
    }

    #[test]
    fn test_parse_list_item_indented() {
        let line = "  - item";
        let result = ListOperations::parse_list_item(line);
        assert_eq!(result, Some((1, false, 4)));
    }

    #[test]
    fn test_parse_list_item_not_list() {
        let line = "regular text";
        let result = ListOperations::parse_list_item(line);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_list_item_rejects_empty_ordered_marker() {
        let line = ". item";
        let result = ListOperations::parse_list_item(line);
        assert_eq!(result, None);
    }

    #[test]
    fn test_empty_ordered_marker_can_be_wrapped_as_list_content() {
        let text = ". item";
        let (new_text, _, _) = ListOperations::create_list(text, 0, text.len(), Operation::CreateOrderedList).unwrap();

        assert_eq!(new_text, "1. . item");
    }

    #[test]
    fn test_nested_list_operations() {
        let text = "- item 1";
        let (new_text, _, _) = ListOperations::indent_list(text, 0, text.len()).unwrap();
        assert_eq!(new_text, "  - item 1");

        let (new_text, _, _) = ListOperations::indent_list(&new_text, 0, new_text.len()).unwrap();
        assert_eq!(new_text, "    - item 1");

        let (new_text, _, _) = ListOperations::unindent_list(&new_text, 0, new_text.len()).unwrap();
        assert_eq!(new_text, "  - item 1");
    }
}
