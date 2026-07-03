/// Parse a line's list prefix. Returns `(indent_level, is_ordered, content_start_byte_offset)`
/// when the line is a list item, or `None` otherwise.
///
/// Shared by [`super::list_operations::ListOperations`] (indent/unindent/create-list) and
/// [`super::newline::NewlineHandler`] (list continuation on Enter) — both need identical
/// parsing so a line is never classified as a list item by one and not the other.
pub(super) fn parse_list_item(line: &str) -> Option<(u8, bool, usize)> {
    let spaces = line.bytes().take_while(|&b| b == b' ').count();
    let level = spaces as u8;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_list_item_unordered() {
        let line = "- item";
        let result = parse_list_item(line);
        assert_eq!(result, Some((0, false, 2)));
    }

    #[test]
    fn test_parse_list_item_ordered() {
        let line = "1. item";
        let result = parse_list_item(line);
        assert_eq!(result, Some((0, true, 3)));
    }

    #[test]
    fn test_parse_list_item_indented() {
        let line = " - item";
        let result = parse_list_item(line);
        assert_eq!(result, Some((1, false, 3)));
    }

    #[test]
    fn test_parse_list_item_not_list() {
        let line = "regular text";
        let result = parse_list_item(line);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_list_item_rejects_empty_ordered_marker() {
        let line = ". item";
        let result = parse_list_item(line);
        assert_eq!(result, None);
    }
}
