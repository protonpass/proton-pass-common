use proptest::prelude::*;
use proton_pass_common::markdown::{MarkdownEditor, Operation, SpanStyle};

// ─── Strategies ───────────────────────────────────────────────────────────────

fn arb_operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::Bold),
        Just(Operation::Italic),
        Just(Operation::Strikethrough),
        Just(Operation::CreateOrderedList),
        Just(Operation::CreateUnorderedList),
        Just(Operation::IndentList),
        Just(Operation::UnindentList),
        Just(Operation::Blockquote),
        Just(Operation::InlineCode),
        Just(Operation::CreateCodeBlock),
        (1u8..=6u8).prop_map(Operation::Header),
    ]
}

/// Plain text that won't accidentally contain markdown syntax.
/// No `*`, `_`, `` ` ``, `~`, `#`, `>`, `-`, digits followed by `.` — keeps toggle tests clean.
fn arb_plain_text() -> impl Strategy<Value = String> {
    "[a-zA-Z ]{1,50}"
}

/// Arbitrary text including common chars, newlines, and unicode — for robustness / no-panic tests.
fn arb_any_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 .,!?@\\n\u{0041}-\u{007e}]{0,80}"
}

/// Text mixing ASCII markdown syntax with multibyte characters (emoji, accented letters,
/// CJK) — regression coverage for byte-boundary panics like cursor_between_empty_markers
/// slicing into the middle of a multibyte char.
fn arb_multibyte_text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            "[a-zA-Z0-9 *_~`#>.\\n-]{0,5}",
            Just("😀".to_string()),
            Just("👋🏽".to_string()),
            Just("café".to_string()),
            Just("你好".to_string()),
            Just("**".to_string()),
            Just("*".to_string()),
        ],
        0..10,
    )
    .prop_map(|parts| parts.concat())
}

/// Text guaranteed to start as an ordered list.
fn arb_ordered_list() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("1. alpha\n2. beta\n3. gamma".to_string()),
        Just("1. only".to_string()),
        Just("1. first\n2. second\n3. third\n4. fourth\n5. fifth".to_string()),
        "[a-zA-Z]{1,8}".prop_map(|w| format!("1. {w}")).prop_flat_map(|first| {
            prop::collection::vec("[a-zA-Z]{1,8}", 1..5).prop_map(move |words| {
                let mut lines = vec![first.clone()];
                for (i, w) in words.iter().enumerate() {
                    lines.push(format!("{}. {w}", i + 2));
                }
                lines.join("\n")
            })
        }),
    ]
}

/// Text guaranteed to start as an unordered list.
fn arb_unordered_list() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("- foo\n- bar\n- baz".to_string()),
        Just("- single".to_string()),
        prop::collection::vec("[a-zA-Z]{1,8}", 1..6)
            .prop_map(|words| { words.iter().map(|w| format!("- {w}")).collect::<Vec<_>>().join("\n") }),
    ]
}

fn arb_list_text() -> impl Strategy<Value = String> {
    prop_oneof![arb_ordered_list(), arb_unordered_list()]
}

/// A sequence of (operation, cursor_ratio ∈ [0,1]) to drive the editor.
fn arb_ops(count: std::ops::Range<usize>) -> impl Strategy<Value = Vec<(Operation, f64)>> {
    prop::collection::vec((arb_operation(), 0.0f64..=1.0f64), count)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn utf16_len(text: &str) -> u32 {
    text.encode_utf16().count() as u32
}

/// Apply a sequence of ops, positioning the cursor using ratios derived from the current text length.
fn apply_ops(editor: &mut MarkdownEditor, ops: &[(Operation, f64)]) {
    for (op, ratio) in ops {
        let len = utf16_len(editor.get_text());
        let pos = (*ratio * len as f64) as u32;
        let _ = editor.set_cursor(pos);
        let _ = editor.apply_operation(*op);
    }
}

/// Returns an error string if any span in `text` violates basic structural invariants.
fn check_span_bounds(text: &str) -> Result<(), String> {
    let spans = MarkdownEditor::new(text.to_string()).render_editor_spans();
    let len = utf16_len(text);
    for span in &spans {
        if span.start > span.end {
            return Err(format!(
                "span.start ({}) > span.end ({}) in {text:?}",
                span.start, span.end
            ));
        }
        if span.end > len {
            return Err(format!("span.end ({}) > utf16_len ({len}) in {text:?}", span.end));
        }
    }
    Ok(())
}

/// True if any span that covers non-backtick text is typed as CodeBlock/Code —
/// which indicates a list item was silently misclassified.
fn list_item_became_code(text: &str) -> bool {
    let spans = MarkdownEditor::new(text.to_string()).render_editor_spans();
    for span in &spans {
        if !matches!(span.style, SpanStyle::CodeBlock | SpanStyle::Code) {
            continue;
        }
        // UTF-16 == UTF-8 for ASCII (all list markers are ASCII), safe to slice.
        let start = span.start as usize;
        let end = (span.end as usize).min(text.len());
        if start < end {
            let slice = &text[start..end];
            if !slice.contains('`') {
                return true;
            }
        }
    }
    false
}

// ─── Properties ──────────────────────────────────────────────────────────────

proptest! {

    // ── 1. No panics ─────────────────────────────────────────────────────────

    /// Any text + any op sequence must not panic.
    #[test]
    fn prop_no_panics(
        text in arb_any_text(),
        ops  in arb_ops(1..20),
    ) {
        let mut editor = MarkdownEditor::new(text);
        apply_ops(&mut editor, &ops);
    }

    /// No panics on empty text.
    #[test]
    fn prop_no_panics_empty_text(ops in arb_ops(1..10)) {
        let mut editor = MarkdownEditor::new(String::new());
        apply_ops(&mut editor, &ops);
    }

    /// No panics when cursor is placed at position 0 or at text length.
    #[test]
    fn prop_no_panics_boundary_cursors(
        text in arb_any_text(),
        op   in arb_operation(),
        at_end in proptest::bool::ANY,
    ) {
        let mut editor = MarkdownEditor::new(text);
        let len = utf16_len(editor.get_text());
        let pos = if at_end { len } else { 0 };
        let _ = editor.set_cursor(pos);
        let _ = editor.apply_operation(op);
    }

    /// No panics when a full-text selection is used for every op.
    #[test]
    fn prop_no_panics_full_selection(
        text in arb_any_text(),
        ops  in arb_ops(1..15),
    ) {
        let mut editor = MarkdownEditor::new(text);
        for (op, _) in &ops {
            let len = utf16_len(editor.get_text());
            let _ = editor.set_selection(0, len);
            let _ = editor.apply_operation(*op);
        }
    }

    /// Any text mixing markdown syntax with multibyte chars (emoji, accents, CJK) + any op
    /// sequence must not panic — regression coverage for byte-boundary slicing bugs.
    #[test]
    fn prop_no_panics_multibyte_text(
        text in arb_multibyte_text(),
        ops  in arb_ops(1..20),
    ) {
        let mut editor = MarkdownEditor::new(text);
        apply_ops(&mut editor, &ops);
    }

    /// insert_text with arbitrary content must not panic.
    #[test]
    fn prop_no_panics_insert_text(
        initial in arb_any_text(),
        inserted in arb_any_text(),
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(initial);
        let len = utf16_len(editor.get_text());
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        let _ = editor.insert_text(&inserted);
    }

    // ── 2. Span structural invariants ────────────────────────────────────────

    /// All spans must satisfy start ≤ end ≤ utf16_len after any op sequence.
    #[test]
    fn prop_span_bounds_always_valid(
        text in arb_any_text(),
        ops  in arb_ops(1..15),
    ) {
        let mut editor = MarkdownEditor::new(text);
        apply_ops(&mut editor, &ops);
        let result = check_span_bounds(editor.get_text());
        prop_assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    /// Span bounds are valid even on the initial text, before any ops.
    #[test]
    fn prop_span_bounds_valid_initial(text in arb_any_text()) {
        let result = check_span_bounds(&text);
        prop_assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    /// render_editor_spans is pure: same text always produces identical spans.
    #[test]
    fn prop_render_is_deterministic(text in arb_any_text()) {
        let a = MarkdownEditor::new(text.clone()).render_editor_spans();
        let b = MarkdownEditor::new(text.clone()).render_editor_spans();
        prop_assert_eq!(a, b, "non-deterministic spans for {:?}", text);
    }

    /// Every MarkdownMarker span must be contained within at least one non-marker parent span.
    #[test]
    fn prop_markers_contained_in_parent(text in arb_any_text()) {
        let spans = MarkdownEditor::new(text.clone()).render_editor_spans();
        let markers: Vec<_> = spans.iter().filter(|s| matches!(s.style, SpanStyle::MarkdownMarker)).collect();
        let parents: Vec<_> = spans.iter().filter(|s| !matches!(s.style, SpanStyle::MarkdownMarker)).collect();
        for m in &markers {
            let contained = parents.iter().any(|p| p.start <= m.start && m.end <= p.end);
            prop_assert!(
                contained,
                "MarkdownMarker {}..{} has no parent span; text={text:?}",
                m.start, m.end
            );
        }
    }

    // ── 3. Cursor invariants ─────────────────────────────────────────────────

    /// Cursor must stay within [0, utf16_len] after every op.
    #[test]
    fn prop_cursor_always_in_bounds(
        text in arb_any_text(),
        ops  in arb_ops(1..20),
    ) {
        let mut editor = MarkdownEditor::new(text);
        for (op, ratio) in &ops {
            let len = utf16_len(editor.get_text());
            let _ = editor.set_cursor((*ratio * len as f64) as u32);
            let _ = editor.apply_operation(*op);
            let cursor = editor.get_cursor();
            let new_len = utf16_len(editor.get_text());
            prop_assert!(
                cursor <= new_len,
                "cursor {cursor} > utf16_len {new_len} after {op:?}"
            );
        }
    }

    // ── 4. Undo / redo invariants ─────────────────────────────────────────────

    /// After an op that changes the text, undo() must restore the previous text.
    #[test]
    fn prop_undo_restores_text(
        text  in arb_any_text(),
        op    in arb_operation(),
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text);
        let len = utf16_len(editor.get_text());
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        let before = editor.get_text().to_string();
        let _ = editor.apply_operation(op);
        let after = editor.get_text().to_string();
        if before != after {
            prop_assert!(editor.undo(), "undo() returned false after op changed text");
            prop_assert_eq!(
                editor.get_text(), before.as_str(),
                "undo did not restore text after {:?}", op
            );
        }
    }

    /// undo() then redo() returns the text to what it was right after the op.
    #[test]
    fn prop_undo_redo_roundtrip(
        text  in arb_any_text(),
        op    in arb_operation(),
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text);
        let len = utf16_len(editor.get_text());
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        let _ = editor.apply_operation(op);
        let after_op = editor.get_text().to_string();
        editor.undo();
        editor.redo();
        prop_assert_eq!(
            editor.get_text(), after_op.as_str(),
            "undo+redo did not return to post-op state for {:?}", op
        );
    }

    /// undo() after N ops + undo all the way back = initial text.
    #[test]
    fn prop_full_undo_restores_initial(
        text in arb_plain_text(),
        ops  in arb_ops(1..15),
    ) {
        let mut editor = MarkdownEditor::new(text.clone());
        apply_ops(&mut editor, &ops);
        while editor.undo() {}
        prop_assert_eq!(
            editor.get_text(), text.as_str(),
            "full undo did not restore initial text"
        );
    }

    /// Undo stack depth is always ≤ 100 regardless of how many ops are applied.
    #[test]
    fn prop_undo_stack_bounded(ops in arb_ops(150..200)) {
        let mut editor = MarkdownEditor::new("some initial text".to_string());
        apply_ops(&mut editor, &ops);
        let mut count = 0u32;
        while editor.undo() {
            count += 1;
            prop_assert!(count <= 100, "undo stack exceeded 100 ({count} undos so far)");
        }
    }

    /// undo() returns false when there is nothing to undo.
    #[test]
    fn prop_undo_false_on_empty_stack(text in arb_any_text()) {
        let mut editor = MarkdownEditor::new(text);
        // Fresh editor — nothing to undo.
        prop_assert!(!editor.undo(), "undo() returned true on a fresh editor");
    }

    /// redo() returns false when there is nothing to redo.
    #[test]
    fn prop_redo_false_when_nothing_to_redo(text in arb_any_text()) {
        let mut editor = MarkdownEditor::new(text);
        prop_assert!(!editor.redo(), "redo() returned true on a fresh editor");
    }

    // ── 5. Formatting toggle invariants ──────────────────────────────────────

    /// Bold applied to full text, then Bold applied to the inner content (between the
    /// markers) restores the original text.
    #[test]
    fn prop_bold_toggle(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(editor.get_text());
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        // Markers are "**" (2 chars each); inner content is at [2, len+2].
        editor.set_selection(2, len + 2).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "Bold toggle did not restore text");
    }

    /// Italic applied twice (full → inner) restores the original text.
    #[test]
    fn prop_italic_toggle(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(editor.get_text());
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        // Markers are "*" (1 char each); inner content at [1, len+1].
        editor.set_selection(1, len + 1).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "Italic toggle did not restore text");
    }

    /// Strikethrough applied twice (full → inner) restores the original text.
    #[test]
    fn prop_strikethrough_toggle(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(editor.get_text());
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::Strikethrough).unwrap();
        // Markers are "~~" (2 chars each); inner content at [2, len+2].
        editor.set_selection(2, len + 2).unwrap();
        editor.apply_operation(Operation::Strikethrough).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "Strikethrough toggle did not restore text");
    }

    /// CreateOrderedList applied twice to a full plain-text selection = original text.
    #[test]
    fn prop_ordered_list_toggle(
        text in "[a-zA-Z \\n]{1,60}",
    ) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(editor.get_text());
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::CreateOrderedList).unwrap();
        let after_first = utf16_len(editor.get_text());
        editor.set_selection(0, after_first).unwrap();
        editor.apply_operation(Operation::CreateOrderedList).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "CreateOrderedList toggle failed");
    }

    /// CreateUnorderedList applied twice to a full plain-text selection = original text.
    #[test]
    fn prop_unordered_list_toggle(
        text in "[a-zA-Z \\n]{1,60}",
    ) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(editor.get_text());
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::CreateUnorderedList).unwrap();
        let after_first = utf16_len(editor.get_text());
        editor.set_selection(0, after_first).unwrap();
        editor.apply_operation(Operation::CreateUnorderedList).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "CreateUnorderedList toggle failed");
    }

    // ── 6. Header invariants ─────────────────────────────────────────────────

    /// Header(N) applied to a plain single-line text produces a line starting with N '#' chars.
    #[test]
    fn prop_header_produces_correct_prefix(
        text  in "[a-zA-Z ]{1,30}",
        level in 1u8..=6u8,
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text);
        let len = utf16_len(editor.get_text());
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        editor.apply_operation(Operation::Header(level)).unwrap();
        let expected = "#".repeat(level as usize) + " ";
        prop_assert!(
            editor.get_text().starts_with(&expected),
            "Header({level}) expected prefix {expected:?}, got {:?}",
            editor.get_text()
        );
    }

    /// Header(N) applied twice to the same line at the same level removes the header.
    #[test]
    fn prop_header_toggle(
        text  in "[a-zA-Z ]{1,30}",
        level in 1u8..=6u8,
    ) {
        let mut editor = MarkdownEditor::new(text.clone());
        editor.set_cursor(0).unwrap();
        editor.apply_operation(Operation::Header(level)).unwrap();
        editor.set_cursor(0).unwrap();
        editor.apply_operation(Operation::Header(level)).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "Header({}) toggle failed", level);
    }

    // ── 7. List invariants ────────────────────────────────────────────────────

    /// List items must never render as CodeBlock after any sequence of list ops.
    #[test]
    fn prop_list_items_never_become_code_blocks(
        text in arb_list_text(),
        ops  in arb_ops(1..30),
    ) {
        let mut editor = MarkdownEditor::new(text);
        let list_ops: Vec<_> = ops
            .into_iter()
            .filter(|(op, _)| matches!(
                op,
                Operation::IndentList | Operation::UnindentList |
                Operation::CreateOrderedList | Operation::CreateUnorderedList
            ))
            .collect();
        apply_ops(&mut editor, &list_ops);
        prop_assert!(
            !list_item_became_code(editor.get_text()),
            "list item misrendered as code block; text={:?}",
            editor.get_text()
        );
    }

    /// IndentList on a list item with no preceding sibling to nest under is a no-op — it has
    /// no safe target column, and indenting anyway is exactly what used to misrender as a
    /// CommonMark code block.
    #[test]
    fn prop_indent_without_parent_is_noop(
        suffix        in "[a-zA-Z]{1,20}",
        marker        in prop_oneof![Just("1. "), Just("- ")],
        leading_spaces in 0usize..=3,
        ratio         in 0.0f64..=1.0f64,
    ) {
        let text = format!("{}{marker}{suffix}", " ".repeat(leading_spaces));
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        let _ = editor.apply_operation(Operation::IndentList);
        prop_assert_eq!(
            editor.get_text(), text.as_str(),
            "IndentList mutated a list item with no valid parent"
        );
    }

    /// UnindentList on a level-0 list item (no leading spaces) is a no-op.
    #[test]
    fn prop_unindent_level0_is_noop(
        suffix in "[a-zA-Z]{1,20}",
        marker in prop_oneof![Just("1. "), Just("- ")],
        ratio  in 0.0f64..=1.0f64,
    ) {
        let text = format!("{marker}{suffix}");
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        let _ = editor.apply_operation(Operation::UnindentList);
        prop_assert_eq!(
            editor.get_text(), text.as_str(),
            "UnindentList mutated a level-0 item"
        );
    }

    /// Indent followed immediately by Unindent on the same item is a no-op.
    #[test]
    fn prop_indent_then_unindent_is_noop(
        text  in arb_list_text(),
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        let pos = (ratio * len as f64) as u32;
        let _ = editor.set_cursor(pos);
        let before = editor.get_text().to_string();
        let _ = editor.apply_operation(Operation::IndentList);
        let after_indent = editor.get_text().to_string();
        if before == after_indent {
            // Already at cap — nothing to test.
            return Ok(());
        }
        let _ = editor.set_cursor(pos);
        let _ = editor.apply_operation(Operation::UnindentList);
        prop_assert_eq!(
            editor.get_text(), before.as_str(),
            "Indent+Unindent was not a no-op"
        );
    }

    /// A freshly created ordered list assigns sequential numbers starting at 1.
    #[test]
    fn prop_ordered_list_sequential_numbers(
        words in prop::collection::vec("[a-zA-Z]{1,10}", 2..8),
    ) {
        let text = words.join("\n");
        let mut editor = MarkdownEditor::new(text);
        let len = utf16_len(editor.get_text());
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::CreateOrderedList).unwrap();
        let result = editor.get_text().to_string();
        for (i, _) in words.iter().enumerate() {
            let expected_prefix = format!("{}. ", i + 1);
            prop_assert!(
                result.contains(&expected_prefix),
                "missing prefix {expected_prefix:?} in ordered list: {result:?}"
            );
        }
    }

    // ── 8. Insert-text invariants ─────────────────────────────────────────────

    /// Text inserted at any position must appear in the final text.
    #[test]
    fn prop_inserted_text_appears_in_result(
        initial  in arb_any_text(),
        inserted in "[a-zA-Z]{1,20}",
        ratio    in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(initial);
        let len = utf16_len(editor.get_text());
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        let _ = editor.insert_text(&inserted);
        prop_assert!(
            editor.get_text().contains(&inserted),
            "inserted text {inserted:?} not found in {:?}",
            editor.get_text()
        );
    }

    /// get_text() length only grows by the inserted string's UTF-16 length.
    #[test]
    fn prop_insert_text_grows_by_exact_length(
        initial  in "[a-zA-Z ]{0,40}",
        inserted in "[a-zA-Z]{1,20}",
        ratio    in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(initial);
        let before_len = utf16_len(editor.get_text());
        let ins_len = utf16_len(&inserted);
        let _ = editor.set_cursor((ratio * before_len as f64) as u32);
        editor.insert_text(&inserted).unwrap();
        let after_len = utf16_len(editor.get_text());
        prop_assert_eq!(
            after_len, before_len + ins_len,
            "text length after insert_text was {}, expected {}",
            after_len, before_len + ins_len
        );
    }

    // ── 9. Mixed-op robustness ────────────────────────────────────────────────

    /// Any mix of formatting ops on list text must not corrupt span bounds.
    #[test]
    fn prop_mixed_ops_on_list_text_span_bounds_valid(
        text in arb_list_text(),
        ops  in arb_ops(1..20),
    ) {
        let mut editor = MarkdownEditor::new(text);
        apply_ops(&mut editor, &ops);
        let result = check_span_bounds(editor.get_text());
        prop_assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    /// Applying a formatting op after CreateOrderedList does not panic.
    #[test]
    fn prop_format_after_list_creation_no_panic(
        text  in "[a-zA-Z \\n]{1,40}",
        op    in arb_operation(),
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text);
        let len = utf16_len(editor.get_text());
        editor.set_selection(0, len).unwrap();
        let _ = editor.apply_operation(Operation::CreateOrderedList);
        let new_len = utf16_len(editor.get_text());
        let _ = editor.set_cursor((ratio * new_len as f64) as u32);
        let _ = editor.apply_operation(op);
    }

    // ── 10. No zero-length spans ──────────────────────────────────────────────

    /// Every span must have start < end (strictly — zero-length spans hint at parser bugs).
    #[test]
    fn prop_no_zero_length_spans(
        text in arb_any_text(),
        ops  in arb_ops(1..15),
    ) {
        let mut editor = MarkdownEditor::new(text);
        apply_ops(&mut editor, &ops);
        let text = editor.get_text().to_string();
        let spans = editor.render_editor_spans();
        for span in &spans {
            prop_assert!(
                span.start < span.end,
                "zero-length span at position {} in {:?}", span.start, text
            );
        }
    }

    // ── 11. UTF-16 surrogate-pair boundaries ──────────────────────────────────

    /// Span boundaries must not fall inside a surrogate pair (Android would slice the string wrong).
    #[test]
    fn prop_spans_dont_split_surrogate_pairs(
        text in arb_any_text(),
        ops  in arb_ops(1..10),
    ) {
        let mut editor = MarkdownEditor::new(text);
        apply_ops(&mut editor, &ops);
        let text = editor.get_text().to_string();
        let utf16: Vec<u16> = text.encode_utf16().collect();
        let spans = editor.render_editor_spans();
        for span in &spans {
            for &pos in &[span.start, span.end] {
                if pos > 0 && (pos as usize) < utf16.len() {
                    let unit = utf16[pos as usize];
                    // Low surrogates (0xDC00–0xDFFF) are always the second half of a pair.
                    prop_assert!(
                        !(0xDC00u16..=0xDFFFu16).contains(&unit),
                        "span boundary {} lands inside a surrogate pair (U+{:04X}) in {:?}",
                        pos, unit, text
                    );
                }
            }
        }
    }

    // ── 12. Redo stack is cleared when a new op follows an undo ───────────────

    /// undo() populates the redo stack; applying a new operation must clear it.
    #[test]
    fn prop_new_op_clears_redo_stack(
        text  in "[a-zA-Z]{5,20}",
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text);
        // Apply Bold so there is something to undo.
        editor.set_selection(0, utf16_len(editor.get_text())).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        editor.undo();
        prop_assert!(editor.can_redo(), "redo stack empty after undo — nothing to clear");
        // Apply a new op — redo stack must be wiped.
        let len = utf16_len(editor.get_text());
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        editor.apply_operation(Operation::CreateUnorderedList).unwrap();
        prop_assert!(!editor.can_redo(), "redo stack not cleared after new op");
    }

    // ── 13. Inline formatting grows the text by an exact number of code units ─

    /// Bold on a plain selection adds exactly 4 UTF-16 code units ("**" × 2).
    #[test]
    fn prop_bold_grows_by_four(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text);
        let before = utf16_len(editor.get_text());
        editor.set_selection(0, before).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        prop_assert_eq!(utf16_len(editor.get_text()), before + 4, "Bold did not add exactly 4 code units");
    }

    /// Italic on a plain selection adds exactly 2 UTF-16 code units ("*" × 2).
    #[test]
    fn prop_italic_grows_by_two(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text);
        let before = utf16_len(editor.get_text());
        editor.set_selection(0, before).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        prop_assert_eq!(utf16_len(editor.get_text()), before + 2, "Italic did not add exactly 2 code units");
    }

    /// Strikethrough on a plain selection adds exactly 4 UTF-16 code units ("~~" × 2).
    #[test]
    fn prop_strikethrough_grows_by_four(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text);
        let before = utf16_len(editor.get_text());
        editor.set_selection(0, before).unwrap();
        editor.apply_operation(Operation::Strikethrough).unwrap();
        prop_assert_eq!(utf16_len(editor.get_text()), before + 4, "Strikethrough did not add exactly 4 code units");
    }

    // ── 14. Header only modifies the current line ─────────────────────────────

    /// Applying Header(N) with the cursor on one line must leave all other lines byte-identical.
    #[test]
    fn prop_header_only_changes_current_line(
        lines    in prop::collection::vec("[a-zA-Z]{1,15}", 2..5usize),
        line_idx in 0usize..5,
        level    in 1u8..=6u8,
    ) {
        let line_idx = line_idx % lines.len();
        let text = lines.join("\n");
        let mut editor = MarkdownEditor::new(text);
        // Place cursor at the start of the target line.
        let cursor: u32 = lines[..line_idx].iter().map(|l| l.len() as u32 + 1 /*\n*/).sum();
        editor.set_cursor(cursor).unwrap();
        editor.apply_operation(Operation::Header(level)).unwrap();
        let result_lines: Vec<&str> = editor.get_text().lines().collect();
        for (i, orig) in lines.iter().enumerate() {
            if i != line_idx {
                prop_assert_eq!(
                    result_lines.get(i).copied().unwrap_or(""),
                    orig.as_str(),
                    "Header({}) changed line {} (not the target line {})", level, i, line_idx
                );
            }
        }
    }

    // ── 15. Blockquote toggle ─────────────────────────────────────────────────

    /// Blockquote applied twice to the same text (full selection both times) restores the original.
    #[test]
    fn prop_blockquote_toggle(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(editor.get_text());
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::Blockquote).unwrap();
        let new_len = utf16_len(editor.get_text());
        editor.set_selection(0, new_len).unwrap();
        editor.apply_operation(Operation::Blockquote).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "Blockquote toggle failed");
    }

    // ── 16. insert_newline splits text at cursor ──────────────────────────────

    /// After insert_newline, the text before the newline is the prefix and after is the suffix.
    #[test]
    fn prop_insert_newline_splits_at_cursor(
        text  in "[a-zA-Z]{1,40}",
        ratio in 0.0f64..=1.0f64,
    ) {
        let split = ((ratio * text.len() as f64) as usize).min(text.len());
        let mut editor = MarkdownEditor::new(text.clone());
        editor.set_cursor(split as u32).unwrap();
        editor.insert_newline().unwrap();
        let result = editor.get_text().to_string();
        let (before, after) = result.split_once('\n').unwrap_or((&result, ""));
        prop_assert_eq!(before, &text[..split], "text before newline wrong");
        prop_assert_eq!(after, &text[split..],  "text after newline wrong");
    }

    // ── 17. delete_range shrinks text by exactly the deleted range ────────────

    /// delete_range(s, e) must reduce the UTF-16 length by exactly (e − s).
    #[test]
    fn prop_delete_range_shrinks_exactly(
        text in "[a-zA-Z]{2,40}",
        a    in 0.0f64..=1.0f64,
        b    in 0.0f64..=1.0f64,
    ) {
        let len = utf16_len(&text);
        let p = ((a * len as f64) as u32).min(len);
        let q = ((b * len as f64) as u32).min(len);
        let (start, end) = if p <= q { (p, q) } else { (q, p) };
        let mut editor = MarkdownEditor::new(text);
        let before = utf16_len(editor.get_text());
        editor.delete_range(start, end).unwrap();
        let after = utf16_len(editor.get_text());
        prop_assert_eq!(after, before - (end - start), "delete_range({},{}) wrong length", start, end);
    }

    // ── 18. delete_selection + undo roundtrip ────────────────────────────────

    /// Deleting a selection and then undoing must restore the original text exactly.
    #[test]
    fn prop_delete_selection_undo(
        text in arb_any_text(),
        a    in 0.0f64..=1.0f64,
        b    in 0.0f64..=1.0f64,
    ) {
        let len = utf16_len(&text);
        let p = ((a * len as f64) as u32).min(len);
        let q = ((b * len as f64) as u32).min(len);
        let (start, end) = if p <= q { (p, q) } else { (q, p) };
        let mut editor = MarkdownEditor::new(text.clone());
        editor.set_selection(start, end).unwrap();
        let before = editor.get_text().to_string();
        if editor.delete_selection().unwrap() {
            editor.undo();
            prop_assert_eq!(editor.get_text(), before.as_str(), "undo after delete_selection failed");
        }
    }

    // ── 19. undo after insert_text ────────────────────────────────────────────

    /// If the editor supports undo for insert_text, it must restore the pre-insert text.
    #[test]
    fn prop_undo_after_insert_text(
        initial  in arb_any_text(),
        inserted in "[a-zA-Z]{1,10}",
        ratio    in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(initial);
        let len = utf16_len(editor.get_text());
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        let before = editor.get_text().to_string();
        editor.insert_text(&inserted).unwrap();
        if editor.can_undo() {
            editor.undo();
            prop_assert_eq!(editor.get_text(), before.as_str(), "undo after insert_text failed");
        }
    }

    // ── 20. OrderedListItem.number matches the digit in the text ──────────────

    /// The `number` field in every OrderedListItem span must equal the actual digit at that position.
    #[test]
    fn prop_ordered_list_number_matches_text(text in arb_ordered_list()) {
        let spans = MarkdownEditor::new(text.clone()).render_editor_spans();
        for span in &spans {
            if let SpanStyle::OrderedListItem { number, .. } = span.style {
                // Ordered list markers are always ASCII, so UTF-16 offset == byte offset.
                let start = span.start as usize;
                if start < text.len() {
                    let slice = &text[start..];
                    let num_str = number.to_string();
                    prop_assert!(
                        slice.starts_with(&num_str),
                        "OrderedListItem {{ number: {number} }} but text at offset {start} starts with {:?}; full text: {:?}",
                        &slice[..num_str.len().min(slice.len())], text
                    );
                }
            }
        }
    }

    // ── 21. Multi-digit ordered list marker spans cover the full "N. " prefix ─

    /// For items ≥ 10, the MarkdownMarker span must cover "10. " (4 chars), not just "1" or "0. ".
    #[test]
    fn prop_multi_digit_marker_covers_full_prefix(
        words in prop::collection::vec("[a-zA-Z]{1,8}", 10..15usize),
    ) {
        let text = words.iter().enumerate()
            .map(|(i, w)| format!("{}. {w}", i + 1))
            .collect::<Vec<_>>()
            .join("\n");
        let spans = MarkdownEditor::new(text.clone()).render_editor_spans();
        for span in &spans {
            if let SpanStyle::OrderedListItem { number, .. } = span.style {
                if number < 10 { continue; }
                let expected_marker = format!("{number}. ");
                // Find the MarkdownMarker child inside this item span.
                let marker = spans.iter().find(|s| {
                    matches!(s.style, SpanStyle::MarkdownMarker)
                        && s.start >= span.start
                        && s.end <= span.end
                });
                if let Some(m) = marker {
                    let start = m.start as usize;
                    let end   = m.end as usize;
                    if start < text.len() {
                        let actual = &text[start..end.min(text.len())];
                        prop_assert_eq!(
                            actual, expected_marker.as_str(),
                            "multi-digit marker for item {}: got {:?}, expected {:?}",
                            number, actual, expected_marker
                        );
                    }
                }
            }
        }
    }

    // ── 22. Bold → Italic → *** roundtrip ────────────────────────────────────

    /// Bold then Italic on plain text produces "***text***"; toggling each back
    /// must restore the intermediate state precisely.  Exercises find_triple_star_positions.
    #[test]
    fn prop_bold_italic_triple_star_roundtrip(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);

        // Step 1: Bold the whole text → "**text**"
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        let after_bold = editor.get_text().to_string();
        prop_assert_eq!(utf16_len(&after_bold), len + 4);

        // Step 2: Italic the inner content [2, len+2] → "***text***"
        editor.set_selection(2, len + 2).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        let after_italic = editor.get_text().to_string();
        prop_assert!(after_italic.starts_with("***"), "expected *** prefix, got {:?}", after_italic);
        prop_assert!(after_italic.ends_with("***"),   "expected *** suffix, got {:?}", after_italic);
        prop_assert_eq!(utf16_len(&after_italic), len + 6);

        // Step 3: Toggle Italic off [3, len+3] — removes one * from each ***  → "**text**"
        editor.set_selection(3, len + 3).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        prop_assert_eq!(editor.get_text(), after_bold.as_str(), "Italic toggle on *** restored wrong text");

        // Step 4: Toggle Bold off [2, len+2] → original plain text
        editor.set_selection(2, len + 2).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "Bold toggle on ** restored wrong text");
    }

    // ── 23. insert_newline continues ordered-list numbering ───────────────────

    /// Pressing Enter at the end of "N. word" must produce "(N+1). " on the new line.
    #[test]
    fn prop_insert_newline_continues_ordered_list(
        word in "[a-zA-Z]{1,10}",
        num  in 1u32..=200u32,
    ) {
        let line = format!("{num}. {word}");
        let mut editor = MarkdownEditor::new(line.clone());
        editor.set_cursor(utf16_len(&line)).unwrap();
        editor.insert_newline().unwrap();
        let expected_next = format!("{}. ", num + 1);
        prop_assert!(
            editor.get_text().contains(&expected_next),
            "insert_newline on {:?} should produce {:?} on next line, got {:?}",
            line, expected_next, editor.get_text()
        );
    }

    // ── 24. Cursor lands inside the markers after formatting ─────────────────

    /// After Bold on the full selection, cursor must be at len+2 (before the closing **,
    /// inside the bold region — matching Obsidian's behaviour so typing continues formatted).
    #[test]
    fn prop_cursor_inside_bold_markers_after_apply(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        prop_assert_eq!(
            editor.get_cursor(), len + 2,
            "cursor not inside bold markers after apply; text={:?}", text
        );
    }

    #[test]
    fn prop_cursor_inside_italic_markers_after_apply(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        prop_assert_eq!(
            editor.get_cursor(), len + 1,
            "cursor not inside italic markers after apply; text={:?}", text
        );
    }

    #[test]
    fn prop_cursor_inside_strikethrough_markers_after_apply(text in arb_plain_text()) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        editor.set_selection(0, len).unwrap();
        editor.apply_operation(Operation::Strikethrough).unwrap();
        prop_assert_eq!(
            editor.get_cursor(), len + 2,
            "cursor not inside strikethrough markers after apply; text={:?}", text
        );
    }

    // ── 25. Word-boundary Bold (no selection) ────────────────────────────────

    /// With cursor strictly inside a word (both surrounding chars are word chars) and no
    /// selection, Bold must format the whole word.  Cursor at the word boundary (position 0
    /// or len of the word) intentionally returns None from find_word_containing_cursor so
    /// that callers get empty markers — this test only probes the interior case.
    #[test]
    fn prop_word_boundary_bold_formats_whole_word(
        prefix in "[a-zA-Z]{1,10}",
        target in "[a-zA-Z]{3,10}", // ≥3 so there is always a strict interior position
        suffix in "[a-zA-Z]{1,10}",
        inner  in 0.0f64..=1.0f64,
    ) {
        // Build "prefix target suffix" and place cursor strictly inside target:
        // interior positions are 1..target.len()-1 (both neighbouring chars are word chars).
        let text = format!("{prefix} {target} {suffix}");
        let word_start = prefix.len() + 1; // +1 for the separating space
        let interior_len = target.len() - 1; // positions 1..=target.len()-1 are valid interiors
        let offset = 1 + ((inner * (interior_len - 1) as f64) as usize).min(interior_len - 1);
        let cursor_pos = word_start + offset;
        let mut editor = MarkdownEditor::new(text);
        editor.set_cursor(cursor_pos as u32).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        let expected = format!("**{target}**");
        prop_assert!(
            editor.get_text().contains(&expected),
            "word-boundary Bold should produce {:?}, got {:?}", expected, editor.get_text()
        );
    }

    // ── 30. Adjacent bold spans and literal asterisks survive toggling ────────

    /// Toggling Bold with the cursor at the "****" junction between two independently
    /// bold-wrapped words must never merge the two words into one bold span.
    #[test]
    fn prop_adjacent_bold_regions_not_merged(
        word1 in "[a-zA-Z]{1,8}",
        word2 in "[a-zA-Z]{1,8}",
    ) {
        let text = format!("**{word1}****{word2}**");
        let junction = (2 + word1.len() + 2) as u32; // cursor between the two inner "**"
        let mut editor = MarkdownEditor::new(text.clone());
        editor.set_cursor(junction).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        prop_assert!(
            editor.get_text().contains(&format!("**{word1}**")),
            "first bold word destroyed: {:?}", editor.get_text()
        );
        prop_assert!(
            editor.get_text().contains(&format!("**{word2}**")),
            "second bold word destroyed: {:?}", editor.get_text()
        );
    }

    /// A literal "*" flanked by whitespace on both sides is not a real emphasis delimiter —
    /// toggling Italic near it must never delete it.
    #[test]
    fn prop_literal_asterisk_never_deleted(
        prefix in "[a-zA-Z]{1,8}",
        suffix in "[a-zA-Z]{1,8}",
    ) {
        let text = format!("{prefix} * {suffix} *");
        let cursor = utf16_len(&text);
        let mut editor = MarkdownEditor::new(text.clone());
        editor.set_cursor(cursor).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        let asterisks_before = text.matches('*').count();
        let asterisks_after = editor.get_text().matches('*').count();
        prop_assert!(
            asterisks_after >= asterisks_before,
            "literal asterisks were deleted: {:?} -> {:?}", text, editor.get_text()
        );
        prop_assert!(
            editor.get_text().starts_with(&text),
            "original literal text was mutated: {:?} -> {:?}", text, editor.get_text()
        );
    }

    // ── 26. replace_range correctness ────────────────────────────────────────

    /// replace_range(s, e, r) must put r at position s and resize the text exactly.
    #[test]
    fn prop_replace_range_content_and_length(
        text        in "[a-zA-Z]{5,30}",
        replacement in "[a-zA-Z]{1,10}",
        a in 0.0f64..=1.0f64,
        b in 0.0f64..=1.0f64,
    ) {
        let len = text.len() as u32; // ASCII → UTF-16 == UTF-8
        let p = ((a * len as f64) as u32).min(len);
        let q = ((b * len as f64) as u32).min(len);
        let (start, end) = if p <= q { (p, q) } else { (q, p) };

        let mut editor = MarkdownEditor::new(text.clone());
        editor.replace_range(start, end, &replacement).unwrap();
        let result = editor.get_text().to_string();

        let s = start as usize;
        let r_len = replacement.len();
        prop_assert!(result.len() >= s + r_len, "result too short after replace_range");
        prop_assert_eq!(
            &result[s..s + r_len], replacement.as_str(),
            "replacement not at expected byte offset {}", s
        );
        let expected_len = text.len() - (end - start) as usize + r_len;
        prop_assert_eq!(result.len(), expected_len, "wrong length after replace_range({},{})", start, end);
    }

    /// replace_range followed by undo must restore the original text.
    #[test]
    fn prop_replace_range_undo(
        text        in "[a-zA-Z]{5,30}",
        replacement in "[a-zA-Z]{1,10}",
        a in 0.0f64..=1.0f64,
        b in 0.0f64..=1.0f64,
    ) {
        let len = text.len() as u32;
        let p = ((a * len as f64) as u32).min(len);
        let q = ((b * len as f64) as u32).min(len);
        let (start, end) = if p <= q { (p, q) } else { (q, p) };

        let mut editor = MarkdownEditor::new(text.clone());
        let before = editor.get_text().to_string();
        editor.replace_range(start, end, &replacement).unwrap();
        if editor.can_undo() {
            editor.undo();
            prop_assert_eq!(editor.get_text(), before.as_str(), "undo after replace_range failed");
        }
    }

    // ── 27. Two non-overlapping Bold ops coexist ──────────────────────────────

    /// Bolding word1 then word2 independently must leave both bold regions intact
    /// and produce valid spans — the second op must not corrupt the first.
    #[test]
    fn prop_two_bold_ops_coexist(
        word1 in "[a-zA-Z]{2,8}",
        word2 in "[a-zA-Z]{2,8}",
    ) {
        // "word1 word2"
        let text = format!("{word1} {word2}");
        let mut editor = MarkdownEditor::new(text);

        // Bold word1: cursor at position 1 (inside word1)
        editor.set_cursor(1).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        // Now: "**word1** word2"
        let after_first = editor.get_text().to_string();
        prop_assert!(after_first.contains(&format!("**{word1}**")), "first bold missing: {:?}", after_first);

        // Bold word2: cursor at end of text (inside word2 after the space)
        let len = utf16_len(&after_first);
        editor.set_cursor(len - 1).unwrap();  // one before end, inside word2
        editor.apply_operation(Operation::Bold).unwrap();
        let after_second = editor.get_text().to_string();
        prop_assert!(after_second.contains(&format!("**{word1}**")), "first bold destroyed: {:?}", after_second);
        prop_assert!(after_second.contains(&format!("**{word2}**")), "second bold missing: {:?}", after_second);

        // Spans must still be valid
        let result = check_span_bounds(&after_second);
        prop_assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    // ── 28. Empty-marker toggle: re-pressing Bold/Italic/Strikethrough removes the markers ─

    /// Applying Bold at a cursor position that is NOT inside a word inserts "****";
    /// applying it again must REMOVE those empty markers.
    /// Uses non-word text (spaces and punctuation only) so the first Bold always
    /// produces empty markers rather than wrapping a word.
    #[test]
    fn prop_empty_bold_toggle_removes_markers(
        text  in "[ .,!?;:]{0,20}",
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        editor.apply_operation(Operation::Bold).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "empty Bold toggle did not restore text");
    }

    #[test]
    fn prop_empty_italic_toggle_removes_markers(
        text  in "[ .,!?;:]{0,20}",
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        editor.apply_operation(Operation::Italic).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "empty Italic toggle did not restore text");
    }

    /// Cursor inside a word → Italic wraps it → Italic again removes it.
    #[test]
    fn prop_word_italic_double_press_removes(
        prefix in "[a-zA-Z]{1,8}",
        target in "[a-zA-Z]{3,10}",
        suffix in "[a-zA-Z]{1,8}",
        inner  in 0.0f64..=1.0f64,
    ) {
        let text = format!("{prefix} {target} {suffix}");
        let word_start = prefix.len() + 1;
        let interior_len = target.len() - 1;
        let offset = 1 + ((inner * (interior_len - 1) as f64) as usize).min(interior_len - 1);
        let cursor_pos = (word_start + offset) as u32;

        let mut editor = MarkdownEditor::new(text.clone());
        editor.set_cursor(cursor_pos).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();
        editor.apply_operation(Operation::Italic).unwrap();

        prop_assert_eq!(editor.get_text(), text.as_str(), "double Italic on word did not restore text");
        let expected_cursor = (word_start + target.len()) as u32;
        prop_assert_eq!(editor.get_cursor(), expected_cursor, "cursor wrong after double Italic");
    }

    /// Cursor inside a word → Strikethrough wraps it → Strikethrough again removes it.
    #[test]
    fn prop_word_strikethrough_double_press_removes(
        prefix in "[a-zA-Z]{1,8}",
        target in "[a-zA-Z]{3,10}",
        suffix in "[a-zA-Z]{1,8}",
        inner  in 0.0f64..=1.0f64,
    ) {
        let text = format!("{prefix} {target} {suffix}");
        let word_start = prefix.len() + 1;
        let interior_len = target.len() - 1;
        let offset = 1 + ((inner * (interior_len - 1) as f64) as usize).min(interior_len - 1);
        let cursor_pos = (word_start + offset) as u32;

        let mut editor = MarkdownEditor::new(text.clone());
        editor.set_cursor(cursor_pos).unwrap();
        editor.apply_operation(Operation::Strikethrough).unwrap();
        editor.apply_operation(Operation::Strikethrough).unwrap();

        prop_assert_eq!(editor.get_text(), text.as_str(), "double Strikethrough on word did not restore text");
        let expected_cursor = (word_start + target.len()) as u32;
        prop_assert_eq!(editor.get_cursor(), expected_cursor, "cursor wrong after double Strikethrough");
    }

    /// Cursor inside a word → Bold wraps it → Bold again removes it and cursor
    /// must stay at the equivalent position (end of the word content), not move
    /// to after the closing marker and nest more markers.
    #[test]
    fn prop_word_bold_double_press_removes(
        prefix in "[a-zA-Z]{1,8}",
        target in "[a-zA-Z]{3,10}",
        suffix in "[a-zA-Z]{1,8}",
        inner  in 0.0f64..=1.0f64,
    ) {
        let text = format!("{prefix} {target} {suffix}");
        let word_start = prefix.len() + 1;
        let interior_len = target.len() - 1;
        let offset = 1 + ((inner * (interior_len - 1) as f64) as usize).min(interior_len - 1);
        let cursor_pos = (word_start + offset) as u32;

        let mut editor = MarkdownEditor::new(text.clone());
        editor.set_cursor(cursor_pos).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();

        // Cursor has moved to end of content (before closing **).
        // Second Bold must toggle off, not add more markers.
        editor.apply_operation(Operation::Bold).unwrap();

        prop_assert_eq!(
            editor.get_text(), text.as_str(),
            "double Bold on word did not restore text"
        );
        // Cursor must be at end of the original word (start + len), not past it.
        let expected_cursor = (word_start + target.len()) as u32;
        prop_assert_eq!(
            editor.get_cursor(), expected_cursor,
            "cursor moved unexpectedly after double Bold"
        );
    }

    #[test]
    fn prop_empty_strikethrough_toggle_removes_markers(
        text  in "[ .,!?;:]{0,20}",
        ratio in 0.0f64..=1.0f64,
    ) {
        let mut editor = MarkdownEditor::new(text.clone());
        let len = utf16_len(&text);
        let _ = editor.set_cursor((ratio * len as f64) as u32);
        editor.apply_operation(Operation::Strikethrough).unwrap();
        editor.apply_operation(Operation::Strikethrough).unwrap();
        prop_assert_eq!(editor.get_text(), text.as_str(), "empty Strikethrough toggle did not restore text");
    }

    // ── 29. Cursor-only formatting never corrupts existing spans ─────────────

    /// Applying Strikethrough (cursor-only, no selection) must never permanently corrupt
    /// existing bold spans.  "~~~~" at line start is a *transient* code-fence state that
    /// resolves as soon as the user types content between the markers; we verify the
    /// after-typing state.  Positions between the two `*` of `**` must be no-ops.
    #[test]
    fn prop_strikethrough_cursor_preserves_bold(
        prefix in "[a-zA-Z ]{0,15}",
        target in "[a-zA-Z]{2,10}",
        suffix in "[a-zA-Z ]{0,15}",
        ratio  in 0.0f64..=1.0f64,
    ) {
        let text = format!("{prefix}\n**{target}** {suffix}");
        let len = utf16_len(&text);
        let pos = (ratio * len as f64) as u32;
        let mut editor = MarkdownEditor::new(text.clone());
        let _ = editor.set_cursor(pos);
        let before = editor.get_text().to_string();
        let _ = editor.apply_operation(Operation::Strikethrough);
        let after_op = editor.get_text().to_string();

        if after_op == before {
            // No-op (cursor between **): original bold must be intact.
            let spans = editor.render_editor_spans();
            let has_bold = spans.iter().any(|s| matches!(s.style, SpanStyle::Bold));
            prop_assert!(has_bold, "no-op lost bold at {pos} in {:?}", text);
        } else {
            // Strikethrough inserted — type a char to flush the transient code-fence state.
            let _ = editor.insert_text("x");
            let result = editor.get_text().to_string();
            if result.contains("**") {
                let spans = editor.render_editor_spans();
                let has_bold = spans.iter().any(|s| matches!(s.style, SpanStyle::Bold));
                prop_assert!(
                    has_bold,
                    "Bold lost after Strikethrough+type at {pos} in {:?}: {:?}",
                    text, result
                );
            }
        }
    }

    /// Same invariant for Bold cursor-only: applying Bold must not corrupt existing
    /// strikethrough or italic spans.
    #[test]
    fn prop_bold_cursor_preserves_strikethrough(
        prefix in "[a-zA-Z ]{0,15}",
        target in "[a-zA-Z]{2,10}",
        suffix in "[a-zA-Z ]{0,15}",
        ratio  in 0.0f64..=1.0f64,
    ) {
        let text = format!("{prefix}\n~~{target}~~ {suffix}");
        let len = utf16_len(&text);
        let pos = (ratio * len as f64) as u32;
        let mut editor = MarkdownEditor::new(text.clone());
        let _ = editor.set_cursor(pos);
        let _ = editor.apply_operation(Operation::Bold);
        let result = editor.get_text().to_string();
        if result.contains("~~") {
            let spans = editor.render_editor_spans();
            let has_st = spans.iter().any(|s| matches!(s.style, SpanStyle::Strikethrough));
            prop_assert!(
                has_st,
                "Strikethrough span lost after Bold at {pos} in {:?}: result={:?}",
                text, result
            );
        }
    }
}
