use super::{MarkdownError, Operation, Result};

/// Result type for operation functions that return new text, cursor position, and optional selection
type OperationResult = Result<(String, u32, Option<(u32, u32)>)>;

/// Operations for applying inline markdown formatting
pub struct MarkdownOperations;

impl MarkdownOperations {
    /// Apply markdown formatting/operations to a text range.
    ///
    /// This includes both inline styling (Bold, Italic, etc.) and structural operations
    /// (CodeBlock, Link) that modify the markdown structure. All operations validate
    /// their input ranges and return consistent error types.
    pub fn apply_inline_formatting(text: &str, start: usize, end: usize, operation: Operation) -> OperationResult {
        if start > end || end > text.len() {
            return Err(MarkdownError::InvalidSelection("Invalid range".to_string()));
        }

        match operation {
            Operation::Bold => Self::toggle_wrapper(text, start, end, "**"),
            Operation::Italic => Self::toggle_wrapper(text, start, end, "*"),
            Operation::Strikethrough => Self::toggle_wrapper(text, start, end, "~~"),
            Operation::InlineCode => Self::toggle_wrapper(text, start, end, "`"),
            Operation::Header(level) => {
                if !(1..=6).contains(&level) {
                    return Err(MarkdownError::InvalidHeaderLevel(format!(
                        "Header level must be 1-6, got {}",
                        level
                    )));
                }
                Self::apply_header(text, start, end, level)
            }
            Operation::Blockquote => {
                // If range is empty (cursor only), return unchanged for block-style operations.
                if start == end {
                    return Ok((text.to_string(), start as u32, None));
                }
                Self::apply_blockquote(text, start, end)
            }
            Operation::CreateCodeBlock => Self::apply_code_block(text, start, end),
            Operation::CreateLink => Self::apply_create_link(text, start, end),
            _ => Err(MarkdownError::InvalidOperation(
                "Not an inline formatting operation".to_string(),
            )),
        }
    }

    /// Toggle a wrapper (like ** for bold) around the selected text
    fn toggle_wrapper(text: &str, start: usize, end: usize, wrapper: &str) -> OperationResult {
        let wrapper_len = wrapper.len();
        let selected_text = &text[start..end];

        if start == end {
            // Cursor sits exactly at the junction of two independent, non-empty wrapped
            // spans (e.g. the "****" between "**a**" and "**b**"). Any of Case 1-3 below
            // would misidentify this as removable/mergeable, corrupting both spans — so
            // treat it like Guard A and leave the text untouched.
            if Self::cursor_at_wrapper_junction(text, start, wrapper) {
                return Ok((text.to_string(), start as u32, None));
            }
            // Case 1: cursor between empty markers (e.g. **|**) → remove them.
            if Self::cursor_between_empty_markers(text, start, wrapper) {
                return Ok((
                    Self::remove_wrapper_pair(text, start - wrapper_len, start, wrapper_len),
                    (start - wrapper_len) as u32,
                    None,
                ));
            }
            // Case 2: cursor right before a closing marker (e.g. **hello|**) →
            // find the matching opening marker and remove the whole wrapper.
            if let Some((opening, closing)) = Self::find_wrapper_before_cursor(text, start, wrapper) {
                return Ok((
                    Self::remove_wrapper_pair(text, opening, closing, wrapper_len),
                    (closing - wrapper_len) as u32,
                    None,
                ));
            }
            // Case 3: cursor right after a closing marker (e.g. **hello**|) →
            // same removal, cursor lands at end of de-formatted content.
            if let Some((opening, closing)) = Self::find_wrapper_after_cursor(text, start, wrapper) {
                return Ok((
                    Self::remove_wrapper_pair(text, opening, closing, wrapper_len),
                    (start - 2 * wrapper_len) as u32,
                    None,
                ));
            }
            // Guard A: don't insert between two identical adjacent delimiter chars (**, ~~, __).
            // Inserting "~~~~" between the two `*` of "**" would split the delimiter pair,
            // turning "**bold**" into "*~~~~*bold**" where bold is no longer recognised.
            if Self::cursor_inside_delimiter_pair(text, start) {
                return Ok((text.to_string(), start as u32, None));
            }
            return Self::insert_empty_wrapper(text, start, wrapper);
        }

        // Special case: Handle *** (bold+italic combined)
        // Search for *** even if there are other wrappers in between
        if (wrapper == "*" || wrapper == "**")
            && let Some(triple_star_pos) = Self::find_triple_star_positions(text, start, end)
        {
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

        // Search for the wrapper, potentially nested within other markdown syntax
        // We need to find matching wrappers that aren't immediately adjacent
        let wrapper_positions = Self::find_wrapper_positions(text, start, end, wrapper);

        if let Some((wrapper_start, wrapper_end)) = wrapper_positions {
            // Remove the wrapper
            let mut new_text = String::new();
            new_text.push_str(&text[..wrapper_start]);
            new_text.push_str(&text[wrapper_start + wrapper_len..wrapper_end]);
            new_text.push_str(&text[wrapper_end + wrapper_len..]);

            Ok((new_text, wrapper_end as u32 - wrapper_len as u32, None))
        } else {
            // Add the wrapper
            let mut new_text = String::new();
            new_text.push_str(&text[..start]);
            new_text.push_str(wrapper);
            new_text.push_str(selected_text);
            new_text.push_str(wrapper);
            new_text.push_str(&text[end..]);

            // Cursor lands before the closing marker — same position Obsidian uses,
            // keeping the user inside the formatted region for continued typing.
            Ok((new_text, (end + wrapper_len) as u32, None))
        }
    }

    /// Returns true when the cursor sits between a matching pair of empty markers
    /// (e.g. cursor at position 2 in "****" for Bold, or position 1 in "**" for Italic).
    /// For the single-char "*" wrapper, ensures the surrounding chars are not part of
    /// a "**" pair so we don't misidentify Bold markers as empty Italic.
    fn cursor_between_empty_markers(text: &str, cursor: usize, wrapper: &str) -> bool {
        let w = wrapper.len();
        if cursor < w || cursor + w > text.len() {
            return false;
        }
        // cursor - w must land on a char boundary (could be inside a multibyte emoji otherwise).
        if !text.is_char_boundary(cursor - w) || !text.is_char_boundary(cursor + w) {
            return false;
        }
        if &text[cursor - w..cursor] != wrapper || &text[cursor..cursor + w] != wrapper {
            return false;
        }
        // For "*" (Italic), reject when the surrounding pattern is actually "**" (Bold).
        if w == 1 {
            let double_before = cursor >= 2 && text.is_char_boundary(cursor - 2) && &text[cursor - 2..cursor] == "**";
            let double_after =
                cursor + 2 <= text.len() && text.is_char_boundary(cursor + 2) && &text[cursor..cursor + 2] == "**";
            if double_before || double_after {
                return false;
            }
        }
        // Reject when either side is actually the delimiter of a real, non-empty span
        // elsewhere (e.g. the "****" junction between "**a**" and "**b**") rather than
        // a genuinely empty "**|**" pair.
        if Self::closes_real_span_before(text, cursor - w, wrapper)
            || Self::opens_real_span_after(text, cursor + w, wrapper)
        {
            return false;
        }
        true
    }

    /// True when the cursor is flanked by `wrapper` on both sides (like
    /// `cursor_between_empty_markers`) AND both flanking tokens belong to real,
    /// non-empty spans elsewhere — i.e. this is the junction of two adjacent spans,
    /// not a genuinely empty pair.
    fn cursor_at_wrapper_junction(text: &str, cursor: usize, wrapper: &str) -> bool {
        let w = wrapper.len();
        if cursor < w || cursor + w > text.len() {
            return false;
        }
        if !text.is_char_boundary(cursor - w) || !text.is_char_boundary(cursor + w) {
            return false;
        }
        if &text[cursor - w..cursor] != wrapper || &text[cursor..cursor + w] != wrapper {
            return false;
        }
        Self::closes_real_span_before(text, cursor - w, wrapper)
            && Self::opens_real_span_after(text, cursor + w, wrapper)
    }

    /// True if `wrapper` occurs earlier in `text` (before `pos`, same line) with non-empty
    /// content between that occurrence and `pos` — meaning the token at `pos` closes a real span.
    fn closes_real_span_before(text: &str, pos: usize, wrapper: &str) -> bool {
        let w = wrapper.len();
        if pos == 0 {
            return false;
        }
        match text[..pos].rfind(wrapper) {
            Some(idx) if idx + w < pos => !text[idx + w..pos].contains('\n'),
            _ => false,
        }
    }

    /// True if `wrapper` occurs later in `text` (from `pos` onward, same line) with non-empty
    /// content between `pos` and that occurrence — meaning the token before `pos` opens a real span.
    fn opens_real_span_after(text: &str, pos: usize, wrapper: &str) -> bool {
        if pos > text.len() {
            return false;
        }
        match text[pos..].find(wrapper) {
            Some(rel_idx) if rel_idx > 0 => !text[pos..pos + rel_idx].contains('\n'),
            _ => false,
        }
    }

    /// Splice out an opening+closing wrapper pair, keeping the content between them.
    fn remove_wrapper_pair(text: &str, opening: usize, closing: usize, w: usize) -> String {
        format!(
            "{}{}{}",
            &text[..opening],
            &text[opening + w..closing],
            &text[closing + w..]
        )
    }

    /// Scan backwards from `before` looking for a standalone wrapper opening marker.
    /// For `"*"` (Italic) rejects candidates that are part of a `"**"` (Bold) pair.
    fn scan_for_opening_marker(text: &str, before: usize, wrapper: &str) -> Option<usize> {
        let w = wrapper.len();
        for (idx, _) in text[..before].char_indices().rev() {
            // Stop at paragraph boundaries — don't match openers from a different paragraph
            if text.as_bytes()[idx] == b'\n' {
                break;
            }
            if idx + w > before || !text.is_char_boundary(idx + w) {
                continue;
            }
            if &text[idx..idx + w] != wrapper {
                continue;
            }
            if w == 1 {
                let star_before = idx >= 1 && text.as_bytes().get(idx - 1) == Some(&b'*');
                let star_after = idx + 2 <= text.len() && text.is_char_boundary(idx + 2) && &text[idx..idx + 2] == "**";
                if star_before || star_after {
                    continue;
                }
            }
            // A real opening delimiter can't be immediately followed by whitespace
            // (e.g. the literal "*" in "a * b *" isn't a valid emphasis opener).
            if !Self::is_valid_opening_marker(text, idx, w) {
                continue;
            }
            return Some(idx);
        }
        None
    }

    /// Whether the char right after a candidate opening marker is non-whitespace,
    /// per CommonMark's left-flanking rule for emphasis delimiters.
    fn is_valid_opening_marker(text: &str, idx: usize, w: usize) -> bool {
        match text[idx + w..].chars().next() {
            Some(c) => !c.is_whitespace(),
            None => false,
        }
    }

    /// Whether the char right before a candidate closing marker is non-whitespace,
    /// per CommonMark's right-flanking rule for emphasis delimiters.
    fn is_valid_closing_marker(text: &str, pos: usize) -> bool {
        if pos == 0 {
            return false;
        }
        text[..pos].chars().next_back().is_some_and(|c| !c.is_whitespace())
    }

    /// When the cursor sits immediately before a closing marker (e.g. `**hello|**`),
    /// return `(opening_byte_pos, closing_byte_pos)` where `closing_byte_pos == cursor`.
    fn find_wrapper_before_cursor(text: &str, cursor: usize, wrapper: &str) -> Option<(usize, usize)> {
        let w = wrapper.len();
        if cursor + w > text.len()
            || !text.is_char_boundary(cursor)
            || !text.is_char_boundary(cursor + w)
            || &text[cursor..cursor + w] != wrapper
        {
            return None;
        }
        if w == 1 {
            if cursor >= 1 && text.as_bytes().get(cursor - 1) == Some(&b'*') {
                return None;
            }
            if cursor + 2 <= text.len() && text.is_char_boundary(cursor + 2) && &text[cursor..cursor + 2] == "**" {
                return None;
            }
        }
        if !Self::is_valid_closing_marker(text, cursor) {
            return None;
        }
        Self::scan_for_opening_marker(text, cursor, wrapper).map(|opening| (opening, cursor))
    }

    /// When the cursor sits immediately after a closing marker (e.g. `**hello**|`),
    /// return `(opening_byte_pos, closing_byte_pos)` where `closing_byte_pos == cursor - w`.
    fn find_wrapper_after_cursor(text: &str, cursor: usize, wrapper: &str) -> Option<(usize, usize)> {
        let w = wrapper.len();
        if cursor < w || !text.is_char_boundary(cursor - w) || !text.is_char_boundary(cursor) {
            return None;
        }
        if &text[cursor - w..cursor] != wrapper {
            return None;
        }
        if w == 1 {
            if cursor >= 2 && text.is_char_boundary(cursor - 2) && &text[cursor - 2..cursor] == "**" {
                return None;
            }
            if cursor < text.len() && text.as_bytes().get(cursor) == Some(&b'*') {
                return None;
            }
        }
        let closing = cursor - w;
        if !Self::is_valid_closing_marker(text, closing) {
            return None;
        }
        Self::scan_for_opening_marker(text, closing, wrapper).map(|opening| (opening, closing))
    }

    /// Returns true when cursor sits between two identical adjacent single-char delimiter
    /// bytes (e.g. cursor between the two `*` of `**`, or the two `~` of `~~`).
    /// Inserting markers here would split the pair and corrupt existing formatting.
    fn cursor_inside_delimiter_pair(text: &str, cursor: usize) -> bool {
        if cursor == 0 || cursor >= text.len() {
            return false;
        }
        let before = text.as_bytes()[cursor - 1];
        let after = text.as_bytes()[cursor];
        before == after && matches!(before, b'*' | b'~' | b'_')
    }

    fn insert_empty_wrapper(text: &str, cursor: usize, wrapper: &str) -> OperationResult {
        let mut new_text = String::with_capacity(text.len() + (wrapper.len() * 2));
        new_text.push_str(&text[..cursor]);
        new_text.push_str(wrapper);
        new_text.push_str(wrapper);
        new_text.push_str(&text[cursor..]);

        Ok((new_text, (cursor + wrapper.len()) as u32, None))
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
            if Self::has_marker_at(text, check_pos, wrapper) {
                // Special case: if looking for "*", make sure it's not part of "**"
                if wrapper == "*" {
                    // Check if there's another * before or after this one
                    let has_star_before = check_pos > 0 && Self::has_marker_at(text, check_pos - 1, "*");
                    let has_star_after = Self::has_marker_at(text, search_start, "*");

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
                    if Self::has_marker_at(text, other_check_pos, other_wrapper) {
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

            if Self::has_marker_at(text, search_end, wrapper) {
                // Special case: if looking for "*", make sure it's not part of "**"
                if wrapper == "*" {
                    // Check if there's another * before or after this one
                    let has_star_before = search_end > 0 && Self::has_marker_at(text, search_end - 1, "*");
                    let has_star_after = Self::has_marker_at(text, search_end + 1, "*");

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
                if *other_wrapper != wrapper
                    && search_end + other_wrapper.len() <= text.len()
                    && Self::has_marker_at(text, search_end, other_wrapper)
                {
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
            if Self::has_marker_at(text, check_pos, "***") {
                // Found it!
                break Some(check_pos);
            }

            // Check if we hit another markdown wrapper - skip over it
            let mut found_other = false;
            for other_wrapper in &wrappers {
                if search_start >= other_wrapper.len() {
                    let other_check_pos = search_start - other_wrapper.len();
                    if Self::has_marker_at(text, other_check_pos, other_wrapper) {
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

            if Self::has_marker_at(text, search_end, "***") {
                // Found it!
                break Some(search_end);
            }

            // Check if we hit another markdown wrapper - skip over it
            let mut found_other = false;
            for other_wrapper in &wrappers {
                if search_end + other_wrapper.len() <= text.len()
                    && Self::has_marker_at(text, search_end, other_wrapper)
                {
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

    fn has_marker_at(text: &str, start: usize, marker: &str) -> bool {
        text.as_bytes()
            .get(start..start + marker.len())
            .is_some_and(|bytes| bytes == marker.as_bytes())
    }

    /// Apply or toggle a fenced code block around the selected text or current line.
    /// Toggle-off: when the line immediately above is ``` and below is ```, remove those fences.
    pub fn apply_code_block(text: &str, start: usize, end: usize) -> OperationResult {
        if start > end || end > text.len() {
            return Err(MarkdownError::InvalidSelection("Invalid range".to_string()));
        }

        // Find the line containing the cursor/start
        let line_start = text[..start].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let line_end = text[start..].find('\n').map(|p| start + p).unwrap_or(text.len());
        let line_content = &text[line_start..line_end];

        // Toggle-off detection: line above is ``` and line below is ```
        // Keep each candidate fence line's own (start, end) span so the splice below can be
        // computed from where they actually matched, rather than assuming a fixed "```\n" byte length.
        let above_span = if line_start > 0 {
            let above_end = line_start - 1; // the \n before this line
            let above_start = text[..above_end].rfind('\n').map(|p| p + 1).unwrap_or(0);
            Some((above_start, above_end))
        } else {
            None
        };
        let below_span = if line_end < text.len() {
            let below_start = line_end + 1;
            let below_end = text[below_start..]
                .find('\n')
                .map(|p| below_start + p)
                .unwrap_or(text.len());
            Some((below_start, below_end))
        } else {
            None
        };
        let line_above = above_span.map(|(s, e)| &text[s..e]).unwrap_or("");
        let line_below = below_span.map(|(s, e)| &text[s..e]).unwrap_or("");

        if line_above == "```" && line_below == "```" {
            // Toggle off: remove the fence lines, spanning from where the opening fence
            // actually starts to just past the closing fence's own trailing newline (if any).
            let (fence_above_start, _) = above_span.expect("line_above matched, so above_span is Some");
            let (_, below_end) = below_span.expect("line_below matched, so below_span is Some");
            let fence_below_end = (below_end + 1).min(text.len());

            let mut new_text = String::new();
            new_text.push_str(&text[..fence_above_start]);
            new_text.push_str(line_content);
            new_text.push_str(&text[fence_below_end..]);

            let new_cursor = (fence_above_start + line_content.len()) as u32;
            return Ok((new_text, new_cursor, None));
        }

        // Apply: wrap selection (or current line) in fences
        let content_start = if start == end { line_start } else { start };
        let content_end = if start == end { line_end } else { end };
        let content = &text[content_start..content_end];

        let opening_fence = "```\n";
        let mut new_text = String::new();
        new_text.push_str(&text[..content_start]);
        new_text.push_str(opening_fence);
        new_text.push_str(content);
        if !content.ends_with('\n') {
            new_text.push('\n');
        }
        new_text.push_str("```");
        new_text.push_str(&text[content_end..]);

        // Cursor lands after the opening fence + newline (start of content)
        let new_cursor = (content_start + opening_fence.len()) as u32;
        Ok((new_text, new_cursor, None))
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

    /// Wraps the selected text (or inserts at cursor) as a markdown link skeleton [text]().
    /// Cursor lands inside the parentheses so the user can type the URL.
    fn apply_create_link(text: &str, start: usize, end: usize) -> OperationResult {
        if start > end || end > text.len() {
            return Err(MarkdownError::InvalidSelection("Invalid range".to_string()));
        }
        let selected = &text[start..end];
        let mut new_text = String::new();
        new_text.push_str(&text[..start]);
        new_text.push('[');
        new_text.push_str(selected);
        new_text.push_str("]()");
        new_text.push_str(&text[end..]);
        // Cursor lands inside "()" — after "[selected]("
        let new_cursor = (start + 1 + selected.len() + 2) as u32;
        Ok((new_text, new_cursor, None))
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
        let (new_text, cursor, selection) =
            MarkdownOperations::apply_inline_formatting(text, 5, 5, Operation::Bold).unwrap();

        assert_eq!(new_text, "hello**** world");
        assert_eq!(cursor, 7);
        assert_eq!(selection, None);
    }

    #[test]
    fn test_italic_cursor_before_emoji_does_not_panic() {
        // Cursor sits between "**" with an emoji (multibyte char) immediately after.
        // double_after must boundary-check cursor+2 before slicing, or this panics.
        let text = "**😀";
        let result = MarkdownOperations::apply_inline_formatting(text, 1, 1, Operation::Italic);
        assert!(result.is_ok());
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

    #[test]
    fn test_inline_code_wraps_selection() {
        let text = "hello world";
        let (new_text, _cursor, _sel) =
            MarkdownOperations::apply_inline_formatting(text, 0, 5, Operation::InlineCode).unwrap();
        assert_eq!(new_text, "`hello` world");
    }

    #[test]
    fn test_inline_code_removes_existing_backticks() {
        let text = "`hello` world";
        let (new_text, _cursor, _sel) =
            MarkdownOperations::apply_inline_formatting(text, 1, 6, Operation::InlineCode).unwrap();
        assert_eq!(new_text, "hello world");
    }

    #[test]
    fn test_inline_code_empty_cursor_inserts_pair() {
        let text = "hello world";
        let (new_text, cursor, _sel) =
            MarkdownOperations::apply_inline_formatting(text, 5, 5, Operation::InlineCode).unwrap();
        assert_eq!(new_text, "hello`` world");
        assert_eq!(cursor, 6);
    }

    #[test]
    fn test_adjacent_bold_regions_not_merged() {
        // Cursor at the "****" junction between two independent bold words must not
        // be treated as an empty **|** pair (which would merge the two words).
        let text = "**a****b**";
        let (new_text, _cursor, _sel) =
            MarkdownOperations::apply_inline_formatting(text, 5, 5, Operation::Bold).unwrap();
        assert_eq!(new_text, "**a****b**");
    }

    #[test]
    fn test_literal_asterisks_not_deleted() {
        // Neither "*" here is a valid emphasis delimiter (both are whitespace-flanked),
        // so toggling Italic must not strip them — it should insert a fresh empty
        // wrapper at the cursor instead, same as pressing Italic anywhere else with
        // no real markers nearby.
        let text = "a * b *";
        let (new_text, _cursor, _sel) =
            MarkdownOperations::apply_inline_formatting(text, 7, 7, Operation::Italic).unwrap();
        assert_eq!(new_text, "a * b ***");
        assert!(
            new_text.starts_with("a * b *"),
            "literal asterisks must survive untouched"
        );
    }
}
