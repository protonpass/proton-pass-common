// Additional integration-style tests for the markdown editor

#[path = "../../test_support/markdown_perf_shapes.rs"]
#[allow(dead_code)]
mod markdown_perf_shapes;

use super::*;

#[test]
fn test_editor_workflow() {
    let mut editor = MarkdownEditor::new("hello world".to_string());

    // Select "hello" and make it bold
    editor.set_selection(0, 5).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "**hello** world");

    // Undo
    assert!(editor.undo());
    assert_eq!(editor.get_text(), "hello world");

    // Redo
    assert!(editor.redo());
    assert_eq!(editor.get_text(), "**hello** world");
}

#[test]
fn test_cursor_word_detection() {
    let mut editor = MarkdownEditor::new("this is a test".to_string());

    // Place cursor in middle of "test"
    editor.set_cursor(12).unwrap(); // 't' in "test"

    // Apply bold - should format the word containing the cursor
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "this is a **test**");
    assert_eq!(editor.get_cursor(), 16);
}

#[test]
fn test_multiple_operations() {
    let mut editor = MarkdownEditor::new("sample text".to_string());

    // Make "sample" bold
    editor.set_selection(0, 6).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "**sample** text");

    // Now make "text" italic
    let text_pos = editor.get_text().find("text").unwrap();
    let text_end = text_pos + 4;
    let text = editor.get_text();
    editor
        .set_selection(
            text[..text_pos].encode_utf16().count() as u32,
            text[..text_end].encode_utf16().count() as u32,
        )
        .unwrap();
    editor.apply_operation(Operation::Italic).unwrap();

    let result = editor.get_text();
    assert!(result.contains("**sample**"));
    assert!(result.contains("*text*"));
}

#[test]
fn test_list_creation_and_indentation() {
    let mut editor = MarkdownEditor::new("item 1\nitem 2\nitem 3".to_string());

    // Create unordered list
    editor
        .set_selection(0, editor.get_text().encode_utf16().count() as u32)
        .unwrap();
    editor.apply_operation(Operation::CreateUnorderedList).unwrap();

    let text = editor.get_text();
    assert!(text.contains("- item 1"));
    assert!(text.contains("- item 2"));
    assert!(text.contains("- item 3"));

    // Indent first item
    editor.set_cursor(0).unwrap();
    editor.apply_operation(Operation::IndentList).unwrap();

    assert!(editor.get_text().starts_with("  - item 1"));
}

#[test]
fn test_header_levels() {
    let mut editor = MarkdownEditor::new("Title".to_string());

    // Apply H1
    editor.set_selection(0, 5).unwrap();
    editor.apply_operation(Operation::Header(1)).unwrap();
    assert_eq!(editor.get_text(), "# Title");

    // Change to H2
    editor.set_cursor(3).unwrap();
    editor.apply_operation(Operation::Header(2)).unwrap();
    assert_eq!(editor.get_text(), "## Title");

    // Remove header
    editor.set_cursor(4).unwrap();
    editor.apply_operation(Operation::Header(2)).unwrap();
    assert_eq!(editor.get_text(), "Title");
}

#[test]
fn test_emoji_handling() {
    let text = "hello 👋🏽 world";
    let mut editor = MarkdownEditor::new(text.to_string());

    // Calculate UTF-16 offsets for the emoji
    let emoji_start_utf8 = "hello ".len();
    let emoji_end_utf8 = emoji_start_utf8 + "👋🏽".len();

    // Convert to UTF-16 for the API
    let emoji_start_utf16 = text[..emoji_start_utf8].encode_utf16().count();
    let emoji_end_utf16 = text[..emoji_end_utf8].encode_utf16().count();

    editor
        .set_selection(emoji_start_utf16 as u32, emoji_end_utf16 as u32)
        .unwrap();
    editor.apply_operation(Operation::Bold).unwrap();

    assert!(editor.get_text().contains("**👋🏽**"));
}

#[test]
fn test_multiline_selection() {
    let mut editor = MarkdownEditor::new("line one\nline two\nline three".to_string());

    // Select across multiple lines
    editor.set_selection(5, 20).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();

    // Should have applied bold
    assert!(editor.get_text().contains("**"));
}

#[test]
fn test_undo_redo_chain() {
    let mut editor = MarkdownEditor::new("text".to_string());

    // Apply bold
    editor.set_selection(0, 4).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "**text**");

    // Apply italic (to the content inside bold)
    editor.set_selection(2, 6).unwrap(); // Select "text" inside **
    editor.apply_operation(Operation::Italic).unwrap();

    let after_italic = editor.get_text();

    // Apply strikethrough
    let text_start = after_italic.find("text").unwrap_or(0);
    let text_end = text_start + 4;
    editor
        .set_selection(
            after_italic[..text_start].encode_utf16().count() as u32,
            after_italic[..text_end].encode_utf16().count() as u32,
        )
        .unwrap();
    editor.apply_operation(Operation::Strikethrough).unwrap();

    // Undo all
    assert!(editor.undo());
    assert!(editor.undo());
    assert!(editor.undo());
    assert_eq!(editor.get_text(), "text");

    // Redo all
    assert!(editor.redo());
    assert!(editor.redo());
    assert!(editor.redo());

    // Should have formatting
    let final_text = editor.get_text();
    assert!(!final_text.is_empty());
    assert!(final_text.contains("text"));
}

#[test]
fn test_set_selection_utf16_len_not_utf8_byte_len() {
    // UTF-8 byte length != UTF-16 code unit count for non-ASCII text.
    // set_selection must receive UTF-16 units; using get_text().len() (UTF-8 bytes) panics.
    // "í" is 2 UTF-8 bytes but 1 UTF-16 code unit.
    let text = "ítem 1\nítem 2\nítem 3"; // each 'í' = 2 bytes, 1 UTF-16 unit
    let mut editor = MarkdownEditor::new(text.to_string());

    let utf16_len = editor.get_text().encode_utf16().count() as u32;
    let utf8_len = editor.get_text().len() as u32;
    assert_ne!(
        utf8_len, utf16_len,
        "test requires non-ASCII text where byte len != utf16 len"
    );

    // Using the UTF-16 length must succeed
    editor.set_selection(0, utf16_len).unwrap();

    // Applying the operation must work correctly
    editor.apply_operation(Operation::CreateUnorderedList).unwrap();
    let result = editor.get_text();
    assert!(
        result.contains("- ítem 1"),
        "expected '- ítem 1' in result, got: {}",
        result
    );
    assert!(
        result.contains("- ítem 2"),
        "expected '- ítem 2' in result, got: {}",
        result
    );
}

#[test]
fn test_empty_text() {
    let mut editor = MarkdownEditor::new(String::new());
    assert_eq!(editor.get_text(), "");

    // Operations on empty text should not crash
    editor.set_cursor(0).unwrap();
    let result = editor.apply_operation(Operation::Bold);
    // Should handle gracefully
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_cursor_at_end() {
    let mut editor = MarkdownEditor::new("hello".to_string());

    editor.set_cursor(5).unwrap();
    // Operations with cursor at end should handle gracefully
    let result = editor.apply_operation(Operation::Bold);
    assert!(result.is_ok());
}

#[test]
fn test_render_after_operations() {
    let mut editor = MarkdownEditor::new("hello world".to_string());

    editor.set_selection(0, 5).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();

    let spans = editor.render_editor_spans();
    let has_bold = spans.iter().any(|s| matches!(s.style, SpanStyle::Bold));
    assert!(has_bold);
}

#[test]
fn test_ordered_list_numbering() {
    let mut editor = MarkdownEditor::new("first\nsecond\nthird".to_string());

    editor
        .set_selection(0, editor.get_text().encode_utf16().count() as u32)
        .unwrap();
    editor.apply_operation(Operation::CreateOrderedList).unwrap();

    let text = editor.get_text();
    assert!(text.contains("1. first"));
    assert!(text.contains("2. second"));
    assert!(text.contains("3. third"));
}

#[test]
fn test_complex_emoji_family() {
    // Family emoji with skin tone modifiers
    let text = "Look 👨‍👩‍👧‍👦 here";
    let mut editor = MarkdownEditor::new(text.to_string());

    let emoji_start_utf8 = "Look ".len();
    let emoji = "👨‍👩‍👧‍👦";
    let emoji_end_utf8 = emoji_start_utf8 + emoji.len();

    // Convert to UTF-16 offsets
    let emoji_start_utf16 = text[..emoji_start_utf8].encode_utf16().count() as u32;
    let emoji_end_utf16 = text[..emoji_end_utf8].encode_utf16().count() as u32;

    editor.set_selection(emoji_start_utf16, emoji_end_utf16).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();

    // Should preserve the emoji correctly
    assert!(editor.get_text().contains(emoji));
    assert!(editor.get_text().contains("**"));
}

#[test]
fn test_newline_in_ordered_list() {
    let mut editor = MarkdownEditor::new("1. First item".to_string());
    editor.set_cursor(13).unwrap(); // End of line
    editor.insert_newline().unwrap();

    assert_eq!(editor.get_text(), "1. First item\n2. ");
    assert_eq!(editor.get_cursor(), 17); // "1. First item" (13) + "\n" (1) + "2. " (3) = 17
}

#[test]
fn test_newline_in_unordered_list() {
    let mut editor = MarkdownEditor::new("- First item".to_string());
    editor.set_cursor(12).unwrap(); // End of line
    editor.insert_newline().unwrap();

    assert_eq!(editor.get_text(), "- First item\n- ");
    assert_eq!(editor.get_cursor(), 15);
}

#[test]
fn test_newline_splits_list_item() {
    let mut editor = MarkdownEditor::new("1. First item".to_string());
    editor.set_cursor(9).unwrap(); // After "First"
    editor.insert_newline().unwrap();

    assert_eq!(editor.get_text(), "1. First \n2. item");
}

#[test]
fn test_newline_exits_empty_list() {
    let mut editor = MarkdownEditor::new("1. Item\n2. ".to_string());
    editor.set_cursor(11).unwrap(); // End of empty item
    editor.insert_newline().unwrap();

    // Keeps the empty item and adds two newlines to exit list
    assert_eq!(editor.get_text(), "1. Item\n2. \n\n");
}

#[test]
fn test_newline_with_undo() {
    let mut editor = MarkdownEditor::new("1. Item".to_string());
    editor.set_cursor(7).unwrap();
    editor.insert_newline().unwrap();

    assert_eq!(editor.get_text(), "1. Item\n2. ");

    editor.undo();
    assert_eq!(editor.get_text(), "1. Item");
}

#[test]
fn test_newline_in_nested_list() {
    let mut editor = MarkdownEditor::new("  - Nested item".to_string());
    editor.set_cursor(15).unwrap();
    editor.insert_newline().unwrap();

    assert_eq!(editor.get_text(), "  - Nested item\n  - ");
    assert_eq!(editor.get_cursor(), 20); // "  - Nested item" (15) + "\n" (1) + "  - " (4) = 20
}

#[test]
fn test_newline_regular_text() {
    let mut editor = MarkdownEditor::new("Regular text".to_string());
    editor.set_cursor(7).unwrap();
    editor.insert_newline().unwrap();

    assert_eq!(editor.get_text(), "Regular\n text");
    assert_eq!(editor.get_cursor(), 8);
}

#[test]
fn test_tab_prefixed_list_newline_is_plain_text_in_v1() {
    let mut editor = MarkdownEditor::new("\t- Item".to_string());
    editor.set_cursor(7).unwrap();
    editor.insert_newline().unwrap();

    assert_eq!(editor.get_text(), "\t- Item\n");
    assert_eq!(editor.get_cursor(), 8);
}

#[test]
fn test_block_formatting_applies_to_selection_start_line_only_in_v1() {
    let mut header_editor = MarkdownEditor::new("First\nSecond".to_string());
    header_editor.set_selection(0, 12).unwrap();
    header_editor.apply_operation(Operation::Header(1)).unwrap();
    assert_eq!(header_editor.get_text(), "# First\nSecond");

    let mut quote_editor = MarkdownEditor::new("First\nSecond".to_string());
    quote_editor.set_selection(0, 12).unwrap();
    quote_editor.apply_operation(Operation::Blockquote).unwrap();
    assert_eq!(quote_editor.get_text(), "> First\nSecond");
}

#[test]
fn test_set_text() {
    let mut editor = MarkdownEditor::new("Hello".to_string());
    assert_eq!(editor.get_cursor(), 5);

    // Save state before changing text
    editor.save_undo_state();

    // Set new text (does not auto-save state)
    editor.set_text("World".to_string());
    assert_eq!(editor.get_text(), "World");
    assert_eq!(editor.get_cursor(), 5); // Cursor at end

    // Undo should restore to saved state
    assert!(editor.undo());
    assert_eq!(editor.get_text(), "Hello");
    assert_eq!(editor.get_cursor(), 5);
}

#[test]
fn test_set_text_adjusts_cursor() {
    let mut editor = MarkdownEditor::new("Hello world".to_string());
    editor.set_cursor(11).unwrap(); // At end

    // Set shorter text - cursor should adjust
    editor.set_text("Hi".to_string());
    assert_eq!(editor.get_text(), "Hi");
    assert_eq!(editor.get_cursor(), 2); // Adjusted to new end
}

#[test]
fn test_insert_text_at_cursor() {
    let mut editor = MarkdownEditor::new("Hello world".to_string());
    editor.set_cursor(5).unwrap(); // After "Hello"

    editor.insert_text(" there").unwrap();
    assert_eq!(editor.get_text(), "Hello there world");
    assert_eq!(editor.get_cursor(), 11); // After inserted text
}

#[test]
fn test_insert_text_replaces_selection() {
    let mut editor = MarkdownEditor::new("Hello world".to_string());
    editor.set_selection(0, 5).unwrap(); // Select "Hello"

    editor.insert_text("Hi").unwrap();
    assert_eq!(editor.get_text(), "Hi world");
    assert_eq!(editor.get_cursor(), 2);
    assert_eq!(editor.get_selection(), None);
}

#[test]
fn test_insert_text_with_emoji() {
    let mut editor = MarkdownEditor::new("Hello".to_string());
    editor.set_cursor(5).unwrap();

    editor.insert_text(" 👋🌍").unwrap();
    assert_eq!(editor.get_text(), "Hello 👋🌍");
}

#[test]
fn test_delete_range() {
    let mut editor = MarkdownEditor::new("Hello world".to_string());

    editor.delete_range(5, 11).unwrap(); // Delete " world"
    assert_eq!(editor.get_text(), "Hello");
    assert_eq!(editor.get_cursor(), 5);

    // Undo
    assert!(editor.undo());
    assert_eq!(editor.get_text(), "Hello world");
}

#[test]
fn test_delete_selection() {
    let mut editor = MarkdownEditor::new("Hello world".to_string());
    editor.set_selection(0, 5).unwrap();

    let deleted = editor.delete_selection().unwrap();
    assert!(deleted);
    assert_eq!(editor.get_text(), " world");
    assert_eq!(editor.get_cursor(), 0);
    assert_eq!(editor.get_selection(), None);
}

#[test]
fn test_delete_selection_no_selection() {
    let mut editor = MarkdownEditor::new("Hello".to_string());

    let deleted = editor.delete_selection().unwrap();
    assert!(!deleted);
    assert_eq!(editor.get_text(), "Hello"); // Unchanged
}

#[test]
fn test_replace_range() {
    let mut editor = MarkdownEditor::new("Hello world".to_string());

    editor.replace_range(0, 5, "Hi").unwrap();
    assert_eq!(editor.get_text(), "Hi world");
    assert_eq!(editor.get_cursor(), 2);

    // Undo
    assert!(editor.undo());
    assert_eq!(editor.get_text(), "Hello world");
}

#[test]
fn test_text_editing_workflow() {
    let mut editor = MarkdownEditor::new("".to_string());

    // User types "Hello"
    editor.insert_text("Hello").unwrap();
    assert_eq!(editor.get_text(), "Hello");

    // User types " world"
    editor.insert_text(" world").unwrap();
    assert_eq!(editor.get_text(), "Hello world");

    // User selects "world" and applies bold
    editor.set_selection(6, 11).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "Hello **world**");

    // User types more after bold (continues being bold - UX preference)
    editor.insert_text("!").unwrap();
    assert_eq!(editor.get_text(), "Hello **world!**");

    // Undo all
    assert!(editor.undo()); // "Hello **world**"
    assert!(editor.undo()); // "Hello world"
    assert!(editor.undo()); // "Hello"
    assert!(editor.undo()); // ""
    assert_eq!(editor.get_text(), "");
}

#[test]
fn test_cursor_at_end_of_word_bold() {
    let mut editor = MarkdownEditor::new("hello world".to_string());
    // Cursor at position 5 (right after "hello")
    editor.set_cursor(5).unwrap();

    // Should insert bold markers at the cursor
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "hello**** world");
    assert_eq!(editor.get_cursor(), 7);
}

#[test]
fn test_cursor_at_end_of_word_italic() {
    let mut editor = MarkdownEditor::new("test item".to_string());
    // Cursor at position 4 (right after "test")
    editor.set_cursor(4).unwrap();

    // Should insert italic markers at the cursor
    editor.apply_operation(Operation::Italic).unwrap();
    assert_eq!(editor.get_text(), "test** item");
    assert_eq!(editor.get_cursor(), 5);
}

#[test]
fn test_cursor_at_end_of_second_word() {
    let mut editor = MarkdownEditor::new("first second".to_string());
    // Cursor at position 12 (right after "second")
    editor.set_cursor(12).unwrap();

    // Should insert bold markers at the cursor
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "first second****");
    assert_eq!(editor.get_cursor(), 14);
}

#[test]
fn test_cursor_at_end_of_text() {
    let mut editor = MarkdownEditor::new("word".to_string());
    // Cursor at end of text
    editor.set_cursor(4).unwrap();

    // Should insert bold markers at the cursor
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "word****");
    assert_eq!(editor.get_cursor(), 6);
}

#[test]
fn test_cursor_at_end_with_emoji() {
    let text = "test👋 next";
    let mut editor = MarkdownEditor::new(text.to_string());
    // Cursor right after emoji - convert UTF-8 to UTF-16
    let emoji_end_utf8 = "test👋".len();
    let emoji_end_utf16 = text[..emoji_end_utf8].encode_utf16().count() as u32;
    editor.set_cursor(emoji_end_utf16).unwrap();

    // Should insert bold markers after the emoji
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "test👋**** next");
    assert_eq!(editor.get_cursor(), emoji_end_utf16 + 2);
}

#[test]
fn test_cursor_in_middle_vs_end_of_word() {
    // Test cursor in middle
    let mut editor1 = MarkdownEditor::new("testing".to_string());
    editor1.set_cursor(3).unwrap(); // Middle of "testing"
    editor1.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor1.get_text(), "**testing**");

    // Test cursor at end
    let mut editor2 = MarkdownEditor::new("testing".to_string());
    editor2.set_cursor(7).unwrap(); // End of "testing"
    editor2.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor2.get_text(), "testing****");

    // Cursor insertion is position-specific.
    assert_ne!(editor1.get_text(), editor2.get_text());
}

#[test]
fn test_apply_blockquote() {
    let mut editor = MarkdownEditor::new("This is a quote".to_string());
    editor.set_selection(0, 4).unwrap();

    editor.apply_operation(Operation::Blockquote).unwrap();
    assert_eq!(editor.get_text(), "> This is a quote");
}

#[test]
fn test_remove_blockquote() {
    let mut editor = MarkdownEditor::new("> This is a quote".to_string());
    editor.set_cursor(5).unwrap();

    editor.apply_operation(Operation::Blockquote).unwrap();
    assert_eq!(editor.get_text(), "This is a quote");
}

#[test]
fn test_toggle_blockquote_with_undo() {
    let mut editor = MarkdownEditor::new("Regular text".to_string());
    editor.set_cursor(5).unwrap();

    // Apply blockquote
    editor.apply_operation(Operation::Blockquote).unwrap();
    assert_eq!(editor.get_text(), "> Regular text");

    // Undo
    assert!(editor.undo());
    assert_eq!(editor.get_text(), "Regular text");

    // Redo
    assert!(editor.redo());
    assert_eq!(editor.get_text(), "> Regular text");
}

#[test]
fn test_blockquote_multiline_second_line() {
    let mut editor = MarkdownEditor::new("First line\nSecond line".to_string());
    editor.set_cursor(15).unwrap(); // In "Second"

    editor.apply_operation(Operation::Blockquote).unwrap();
    assert_eq!(editor.get_text(), "First line\n> Second line");
}

#[test]
fn test_nested_formatting_toggle() {
    // Reproduce the bug: strikethrough -> bold -> strikethrough should remove strikethrough
    let mut editor = MarkdownEditor::new("text".to_string());

    // Step 1: Apply strikethrough to the selected word
    select_ascii_text(&mut editor, "text");
    editor.apply_operation(Operation::Strikethrough).unwrap();
    assert_eq!(editor.get_text(), "~~text~~");

    // Step 2: Apply bold to the selected word
    select_ascii_text(&mut editor, "text");
    editor.apply_operation(Operation::Bold).unwrap();
    let after_bold = editor.get_text();

    // Should be ~~**text**~~ or **~~text~~** depending on where cursor ended up
    // Both are valid, but it should contain both ~~ and **
    assert!(after_bold.contains("~~"));
    assert!(after_bold.contains("**"));
    assert!(after_bold.contains("text"));

    // Step 3: Apply strikethrough again - should REMOVE it, not add it twice
    select_ascii_text(&mut editor, "text");
    editor.apply_operation(Operation::Strikethrough).unwrap();
    let final_text = editor.get_text();

    // Should only have ** left, no ~~
    assert!(final_text.contains("**"));
    assert!(
        !final_text.contains("~~"),
        "Expected strikethrough to be removed, but got: {}",
        final_text
    );
    assert_eq!(final_text, "**text**");
}

#[test]
fn test_nested_bold_italic_toggle() {
    // Test: italic -> bold -> italic should remove italic
    let mut editor = MarkdownEditor::new("word".to_string());

    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Italic).unwrap();
    assert_eq!(editor.get_text(), "*word*");

    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Bold).unwrap();
    let after_bold = editor.get_text();
    assert!(after_bold.contains("*"));
    assert!(after_bold.contains("**"));

    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Italic).unwrap();
    let final_text = editor.get_text();
    // After toggling italic on ***word***, we should have **word** (italic removed, bold remains)
    assert_eq!(final_text, "**word**");
}

#[test]
fn test_cursor_after_italic_removed_from_bold_italic() {
    // Cursor must not land inside a marker after toggle.
    // ***word*** → italic off → **word** (8 chars: ** word **)
    // Closing ** starts at position 6. Cursor at 6 = between 'd' and '*' = valid.
    // Cursor at 7 = between the two '*' = INSIDE the closing marker = wrong.
    let mut editor = MarkdownEditor::new("***word***".to_string());
    editor.set_selection(3, 7).unwrap(); // select "word"
    editor.apply_operation(Operation::Italic).unwrap();
    assert_eq!(editor.get_text(), "**word**");
    let cursor = editor.get_cursor();
    // Valid positions: 0..=8. Must not be 7 (inside closing **).
    assert_ne!(cursor, 7, "cursor must not land between the two closing asterisks");
    // Cursor should be at the end of the content (6), not past the closing marker
    assert_eq!(cursor, 6, "cursor should be at end of content, before closing **");
}

#[test]
fn test_cursor_after_bold_removed_from_bold_italic() {
    // ***word*** → bold off → *word* (6 chars)
    // Closing * is at position 5. Cursor must not land inside it.
    let mut editor = MarkdownEditor::new("***word***".to_string());
    editor.set_selection(3, 7).unwrap(); // select "word"
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "*word*");
    let cursor = editor.get_cursor();
    assert_eq!(cursor, 5, "cursor should be at end of content, before closing *");
}

#[test]
fn test_nested_bold_strikethrough_toggle() {
    // Test: bold -> strikethrough -> bold should remove bold
    let mut editor = MarkdownEditor::new("test".to_string());

    select_ascii_text(&mut editor, "test");
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "**test**");

    select_ascii_text(&mut editor, "test");
    editor.apply_operation(Operation::Strikethrough).unwrap();
    assert!(editor.get_text().contains("**"));
    assert!(editor.get_text().contains("~~"));

    select_ascii_text(&mut editor, "test");
    editor.apply_operation(Operation::Bold).unwrap();
    let final_text = editor.get_text();
    assert!(!final_text.contains("**"), "Expected bold to be removed");
    assert_eq!(final_text, "~~test~~");
}

#[test]
fn test_triple_nested_formatting() {
    // Test: strikethrough -> italic -> bold -> remove each in order
    let mut editor = MarkdownEditor::new("word".to_string());

    // Apply all three
    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Strikethrough).unwrap();
    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Italic).unwrap();
    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Bold).unwrap();

    let triple = editor.get_text();
    assert!(triple.contains("~~"), "Should have strikethrough");
    assert!(triple.contains("*"), "Should have italic");
    assert!(triple.contains("**"), "Should have bold");

    // Remove bold
    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Bold).unwrap();
    let after_bold = editor.get_text();
    assert!(!after_bold.contains("**"), "Bold should be removed");
    assert!(after_bold.contains("*"), "Italic should remain");
    assert!(after_bold.contains("~~"), "Strikethrough should remain");

    // Remove italic
    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Italic).unwrap();
    let after_italic = editor.get_text();
    assert!(!after_italic.contains("*"), "Italic should be removed");
    assert!(after_italic.contains("~~"), "Strikethrough should remain");

    // Remove strikethrough
    select_ascii_text(&mut editor, "word");
    editor.apply_operation(Operation::Strikethrough).unwrap();
    assert_eq!(editor.get_text(), "word", "All formatting should be removed");
}

#[test]
fn test_nested_toggle_different_order() {
    // Test removing in different order than applying
    let mut editor = MarkdownEditor::new("text".to_string());

    // Apply: italic -> bold -> strikethrough
    select_ascii_text(&mut editor, "text");
    editor.apply_operation(Operation::Italic).unwrap();
    select_ascii_text(&mut editor, "text");
    editor.apply_operation(Operation::Bold).unwrap();
    select_ascii_text(&mut editor, "text");
    editor.apply_operation(Operation::Strikethrough).unwrap();

    // Remove: italic (should reduce *** to **)
    select_ascii_text(&mut editor, "text");
    editor.apply_operation(Operation::Italic).unwrap();
    let after = editor.get_text();
    // After removing italic from ***~~text~~***, we should have **~~text~~**
    // (bold outside, strikethrough inside, because that's the order they were applied)
    assert!(after.contains("**"), "Bold should remain");
    assert!(after.contains("~~"), "Strikethrough should remain");
    assert!(after.starts_with("**~~"), "Should start with **~~");
    assert_eq!(after, "**~~text~~**");
}

#[test]
fn test_markdown_document_node_lookup() {
    let document = MarkdownDocument {
        nodes: vec![MarkdownNode {
            id: MarkdownNodeId(0),
            parent: None,
            children: smallvec::smallvec![MarkdownNodeId(1)],
            kind: MarkdownNodeKind::Paragraph,
        }],
        root: vec![MarkdownNodeId(0)],
    };

    assert!(matches!(
        document.node(MarkdownNodeId(0)).unwrap().kind,
        MarkdownNodeKind::Paragraph
    ));
    assert!(document.node(MarkdownNodeId(1)).is_none());
}

#[test]
fn test_parse_basic_document_to_ir() {
    let document = parse_markdown_document("# Title\n\nHello **world**").unwrap();

    assert_eq!(document.root.len(), 2);
    assert!(matches!(
        document.node(document.root[0]).unwrap().kind,
        MarkdownNodeKind::Heading { level: 1 }
    ));
    assert!(document
        .nodes
        .iter()
        .any(|node| matches!(node.kind, MarkdownNodeKind::Strong)));
}

#[test]
fn test_parse_raw_html_as_literal_text() {
    let document = parse_markdown_document("Click <kbd>Enter</kbd>").unwrap();
    let text_nodes = document
        .nodes
        .iter()
        .filter_map(|node| match &node.kind {
            MarkdownNodeKind::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(text_nodes, vec!["Click <kbd>Enter</kbd>"]);
}

#[test]
fn test_parse_link_safety_policy() {
    let document = parse_markdown_document(
        "[safe](HTTPS://Example.COM/Path) [userinfo](https://user:pass@example.com/) [fragment](#section)",
    )
    .unwrap();

    assert!(document.nodes.iter().any(|node| {
        matches!(
            &node.kind,
            MarkdownNodeKind::Link {
                destination: MarkdownLink::Safe {
                    href,
                    scheme: MarkdownLinkScheme::Https,
                },
                ..
            } if href == "HTTPS://Example.COM/Path"
        )
    }));

    assert!(document.nodes.iter().any(|node| {
        matches!(
            &node.kind,
            MarkdownNodeKind::Link {
                destination: MarkdownLink::Unsafe {
                    reason: MarkdownUnsafeLinkReason::UserInfo,
                    ..
                },
                ..
            }
        )
    }));

    assert!(document.nodes.iter().any(|node| {
        matches!(
            &node.kind,
            MarkdownNodeKind::Link {
                destination: MarkdownLink::Unsafe {
                    reason: MarkdownUnsafeLinkReason::RelativeOrFragment,
                    ..
                },
                ..
            }
        )
    }));
}

#[test]
fn test_parse_code_block_preserves_content() {
    let markdown = "```rust\nfn main() {\n    println!(\"hi\");\n}\n```";
    let document = parse_markdown_document(markdown).unwrap();

    assert!(document.nodes.iter().any(|node| {
        matches!(
            &node.kind,
            MarkdownNodeKind::CodeBlock {
                language: Some(language),
                code,
            } if language == "rust" && code == "fn main() {\n    println!(\"hi\");\n}\n"
        )
    }));
}

#[test]
fn test_parse_rejects_document_over_input_limit() {
    let limits = MarkdownParseLimits {
        max_input_bytes: 4,
        ..MarkdownParseLimits::default()
    };

    let error = parse_markdown_document_with_limits("hello", limits).unwrap_err();
    assert!(matches!(error, MarkdownError::DocumentTooLarge(_)));
}

#[test]
fn test_parse_rejects_too_many_nodes() {
    let limits = MarkdownParseLimits {
        max_nodes: 1,
        ..MarkdownParseLimits::default()
    };

    let error = parse_markdown_document_with_limits("hello **world**", limits).unwrap_err();
    assert!(matches!(error, MarkdownError::TooManyNodes(_)));
}

#[test]
fn test_parse_rejects_plain_text_over_node_limit() {
    let limits = MarkdownParseLimits {
        max_nodes: 1,
        ..MarkdownParseLimits::default()
    };

    let error = parse_markdown_document_with_limits("hello", limits).unwrap_err();
    assert!(matches!(error, MarkdownError::TooManyNodes(_)));
}

#[test]
fn test_parse_unsupported_image_does_not_close_paragraph() {
    let document = parse_markdown_document("before ![ignored](https://example.com/image.png) after").unwrap();
    assert_valid_markdown_document(&document);

    assert_eq!(document.root.len(), 1);
    let paragraph = document.node(document.root[0]).unwrap();
    assert!(matches!(paragraph.kind, MarkdownNodeKind::Paragraph));

    let paragraph_text = paragraph
        .children
        .iter()
        .filter_map(|id| document.node(*id))
        .filter_map(|node| match &node.kind {
            MarkdownNodeKind::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<String>();

    assert_eq!(paragraph_text, "before ignored after");
}

#[test]
fn test_parse_unsupported_table_does_not_close_paragraph() {
    let markdown = "before\n\n| a |\n| - |\n| b |\n\nafter";
    let document = parse_markdown_document(markdown).unwrap();
    assert_valid_markdown_document(&document);

    assert!(document
        .root
        .iter()
        .filter_map(|id| document.node(*id))
        .any(|node| matches!(node.kind, MarkdownNodeKind::Paragraph)));
}

#[test]
fn test_parse_rejects_oversized_code_block() {
    let limits = MarkdownParseLimits {
        max_code_block_bytes: 3,
        ..MarkdownParseLimits::default()
    };

    let error = parse_markdown_document_with_limits("```\nhello\n```", limits).unwrap_err();
    assert!(matches!(error, MarkdownError::PayloadTooLarge(_)));
}

#[test]
fn test_link_classifier_rejects_unsupported_and_control_links() {
    assert!(matches!(
        classify_markdown_link("javascript:alert(1)"),
        MarkdownLink::Unsafe {
            reason: MarkdownUnsafeLinkReason::UnsupportedScheme,
            ..
        }
    ));

    assert!(matches!(
        classify_markdown_link("https://example.com/\nnext"),
        MarkdownLink::Unsafe {
            reason: MarkdownUnsafeLinkReason::ControlCharacter,
            ..
        }
    ));

    assert!(matches!(
        classify_markdown_link("mailto:foo"),
        MarkdownLink::Safe {
            scheme: MarkdownLinkScheme::Mailto,
            ..
        }
    ));

    assert!(matches!(
        classify_markdown_link("tel:+123"),
        MarkdownLink::Unsafe {
            reason: MarkdownUnsafeLinkReason::UnsupportedScheme,
            ..
        }
    ));
}

#[test]
fn test_link_classifier_security_contract_edges() {
    assert_eq!(
        classify_markdown_link(" HTTPS://Example.COM/Path "),
        MarkdownLink::Safe {
            href: "HTTPS://Example.COM/Path".to_string(),
            scheme: MarkdownLinkScheme::Https,
        }
    );
    assert_eq!(
        classify_markdown_link("https://user:pass@example.com/"),
        MarkdownLink::Unsafe {
            raw: "https://user:pass@example.com/".to_string(),
            reason: MarkdownUnsafeLinkReason::UserInfo,
        }
    );
    assert_eq!(
        classify_markdown_link("#section"),
        MarkdownLink::Unsafe {
            raw: "#section".to_string(),
            reason: MarkdownUnsafeLinkReason::RelativeOrFragment,
        }
    );
    assert_eq!(
        classify_markdown_link("https%3A//example.com"),
        MarkdownLink::Unsafe {
            raw: "https%3A//example.com".to_string(),
            reason: MarkdownUnsafeLinkReason::Malformed,
        }
    );
}

#[test]
fn test_link_classifier_fast_path_contract_edges() {
    assert_eq!(
        classify_markdown_link("JaVaScRiPt:alert(1)"),
        MarkdownLink::Unsafe {
            raw: "JaVaScRiPt:alert(1)".to_string(),
            reason: MarkdownUnsafeLinkReason::UnsupportedScheme,
        }
    );
    assert_eq!(
        classify_markdown_link("HTTPS://example.com/%3A/path"),
        MarkdownLink::Safe {
            href: "HTTPS://example.com/%3A/path".to_string(),
            scheme: MarkdownLinkScheme::Https,
        }
    );
    assert_eq!(
        classify_markdown_link("https://example.com/path%3a"),
        MarkdownLink::Safe {
            href: "https://example.com/path%3a".to_string(),
            scheme: MarkdownLinkScheme::Https,
        }
    );
    assert_eq!(
        classify_markdown_link("https://example.com/path?q=hello%3Aworld"),
        MarkdownLink::Safe {
            href: "https://example.com/path?q=hello%3Aworld".to_string(),
            scheme: MarkdownLinkScheme::Https,
        }
    );
    assert_eq!(
        classify_markdown_link("mailto:UPPER@example.com"),
        MarkdownLink::Safe {
            href: "mailto:UPPER@example.com".to_string(),
            scheme: MarkdownLinkScheme::Mailto,
        }
    );
}

#[test]
fn test_mailto_with_userinfo_is_unsafe() {
    assert_eq!(
        classify_markdown_link("mailto:user:pass@host"),
        MarkdownLink::Unsafe {
            raw: "mailto:user:pass@host".to_string(),
            reason: MarkdownUnsafeLinkReason::UserInfo,
        }
    );
    assert_eq!(
        classify_markdown_link("MAILTO:victim:secret@attacker.com"),
        MarkdownLink::Unsafe {
            raw: "MAILTO:victim:secret@attacker.com".to_string(),
            reason: MarkdownUnsafeLinkReason::UserInfo,
        }
    );
}

#[test]
fn test_parse_markdown_fixture_contract() {
    let text = include_str!("../../test_data/markdown/shared_renderer.md");
    let document = parse_markdown_document(text).unwrap();

    assert_valid_markdown_document(&document);
    assert_eq!(document.root.len(), 6);
    assert!(document
        .nodes
        .iter()
        .any(|node| matches!(node.kind, MarkdownNodeKind::Heading { level: 1 })));
    assert!(document
        .nodes
        .iter()
        .any(|node| matches!(node.kind, MarkdownNodeKind::Strong)));
    assert!(document.nodes.iter().any(|node| {
        matches!(
            &node.kind,
            MarkdownNodeKind::Link {
                destination: MarkdownLink::Safe {
                    href,
                    scheme: MarkdownLinkScheme::Https,
                },
                ..
            } if href == "HTTPS://Example.COM/Path"
        )
    }));
    assert!(document.nodes.iter().any(|node| {
        matches!(
            &node.kind,
            MarkdownNodeKind::Link {
                destination: MarkdownLink::Unsafe {
                    raw,
                    reason: MarkdownUnsafeLinkReason::UnsupportedScheme,
                },
                ..
            } if raw == "javascript:alert(1)"
        )
    }));
    assert!(document.nodes.iter().any(|node| {
        matches!(
            &node.kind,
            MarkdownNodeKind::CodeBlock {
                language: Some(language),
                code,
            } if language == "rust" && code == "fn main() {\n    println!(\"hi\");\n}\n"
        )
    }));
    let rendered_text = document
        .nodes
        .iter()
        .filter_map(|node| match &node.kind {
            MarkdownNodeKind::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<String>();
    assert!(rendered_text.contains("<kbd>Enter</kbd>"));
}

#[test]
fn test_benchmark_shape_outputs_stay_bounded() {
    let cases = [
        ("link_heavy", markdown_perf_shapes::link_heavy_note(128), 1_100),
        ("inline_heavy", markdown_perf_shapes::inline_heavy_note(256), 3_200),
        ("deep_structure", markdown_perf_shapes::deep_in_budget_structure(), 250),
        (
            "large_code_block",
            markdown_perf_shapes::large_code_block_note(120 * 1024),
            8,
        ),
    ];

    for (name, markdown, max_nodes) in cases {
        assert!(
            markdown.len() <= MarkdownParseLimits::default().max_input_bytes,
            "{name} fixture must stay inside the default input budget"
        );

        let document = parse_markdown_document(&markdown).unwrap_or_else(|error| {
            panic!("{name} fixture should parse inside default budgets, got {error:?}");
        });
        assert_valid_markdown_document(&document);
        assert!(
            document.nodes.len() <= max_nodes,
            "{name} produced {} nodes, expected at most {max_nodes}",
            document.nodes.len()
        );
    }
}

#[test]
fn test_performance_shape_helper_is_behavior_preserving() {
    let document = parse_markdown_document(&markdown_perf_shapes::link_heavy_note(2)).unwrap();

    let safe_links = document
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                &node.kind,
                MarkdownNodeKind::Link {
                    destination: MarkdownLink::Safe { .. },
                    ..
                }
            )
        })
        .count();
    let unsafe_links = document
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                &node.kind,
                MarkdownNodeKind::Link {
                    destination: MarkdownLink::Unsafe { .. },
                    ..
                }
            )
        })
        .count();

    assert_eq!(safe_links, 2);
    assert_eq!(unsafe_links, 2);
}

#[test]
fn test_parse_generated_adversarial_corpus_is_bounded_and_well_formed() {
    for markdown in generated_markdown_corpus() {
        let parse_result = std::panic::catch_unwind(|| parse_markdown_document(&markdown));
        assert!(parse_result.is_ok(), "parser panicked for input: {markdown:?}");

        match parse_result.unwrap() {
            Ok(document) => assert_valid_markdown_document(&document),
            Err(
                MarkdownError::DocumentTooLarge(_)
                | MarkdownError::TooDeep(_)
                | MarkdownError::TooManyNodes(_)
                | MarkdownError::PayloadTooLarge(_),
            ) => {}
            Err(error) => panic!("unexpected parser error for {markdown:?}: {error:?}"),
        }
    }
}

#[test]
fn test_editor_generated_unicode_operations_do_not_panic() {
    let operations = [
        Operation::Bold,
        Operation::Italic,
        Operation::Strikethrough,
        Operation::Header(1),
        Operation::Header(3),
        Operation::Blockquote,
        Operation::CreateOrderedList,
        Operation::CreateUnorderedList,
        Operation::IndentList,
        Operation::UnindentList,
    ];

    for text in generated_editor_corpus() {
        let offsets = utf16_boundaries(&text);
        for cursor in offsets.iter().copied() {
            for operation in operations {
                let text = text.clone();
                let result = std::panic::catch_unwind(move || {
                    let mut editor = MarkdownEditor::new(text);
                    editor.set_cursor(cursor).unwrap();
                    let _ = editor.apply_operation(operation);
                    assert_valid_editor_state(&editor);
                });
                assert!(
                    result.is_ok(),
                    "editor operation {operation:?} panicked at cursor {cursor}"
                );
            }
        }
    }
}

#[test]
fn test_editor_generated_unicode_selections_do_not_panic() {
    for text in generated_editor_corpus() {
        let offsets = utf16_boundaries(&text);
        for window in offsets.windows(2) {
            let start = window[0];
            let end = window[1];
            let text = text.clone();
            let result = std::panic::catch_unwind(move || {
                let mut editor = MarkdownEditor::new(text);
                editor.set_selection(start, end).unwrap();
                editor.apply_operation(Operation::Bold).unwrap();
                assert_valid_editor_state(&editor);
            });
            assert!(result.is_ok(), "editor selection panicked for {start}..{end}");
        }
    }
}

#[test]
fn test_utf16_invalid_generated_offsets_are_rejected() {
    for text in generated_editor_corpus() {
        let max_offset = text.encode_utf16().count() as u32;
        let valid_offsets = utf16_boundaries(&text);

        for offset in 0..=max_offset {
            if valid_offsets.contains(&offset) {
                continue;
            }

            let mut editor = MarkdownEditor::new(text.clone());
            assert!(
                matches!(editor.set_cursor(offset), Err(MarkdownError::InvalidCursorPosition(_))),
                "invalid UTF-16 cursor offset {offset} was accepted for {text:?}",
            );
            assert!(
                matches!(editor.set_selection(0, offset), Err(MarkdownError::InvalidSelection(_))),
                "invalid UTF-16 selection offset {offset} was accepted for {text:?}",
            );
        }
    }
}

fn assert_valid_markdown_document(document: &MarkdownDocument) {
    for root_id in &document.root {
        let root = document.node(*root_id).expect("root id must point to a node");
        assert_eq!(root.parent, None, "root nodes must not have a parent");
    }

    for node in &document.nodes {
        assert_eq!(
            document.node(node.id),
            Some(node),
            "node ids must map back to their node"
        );

        if let Some(parent_id) = node.parent {
            let parent = document.node(parent_id).expect("parent id must point to a node");
            assert!(
                parent.children.contains(&node.id),
                "parent must include child id {:?}",
                node.id
            );
        }

        for child_id in &node.children {
            let child = document.node(*child_id).expect("child id must point to a node");
            assert_eq!(child.parent, Some(node.id), "child must point back to parent");
        }
    }
}

fn assert_valid_editor_state(editor: &MarkdownEditor) {
    let text = editor.get_text();
    let cursor = editor.get_cursor();
    let max_cursor = text.encode_utf16().count() as u32;
    assert!(cursor <= max_cursor, "cursor must stay within UTF-16 text length");
    assert!(editor.render_editor_spans().iter().all(|span| span.start <= span.end));
}

fn select_ascii_text(editor: &mut MarkdownEditor, needle: &str) {
    let start = editor.get_text().find(needle).unwrap();
    editor
        .set_selection(start as u32, (start + needle.len()) as u32)
        .unwrap();
}

fn generated_markdown_corpus() -> Vec<String> {
    let seeds = [
        "",
        "# Heading\n\nParagraph **bold** *italic* ~~strike~~",
        "[safe](https://example.com) [bad](javascript:alert(1)) [fragment](#x)",
        "Click <kbd>Enter</kbd> & <script>alert(1)</script>",
        "1. one\n2. two\n   - nested\n\n> quote `code`",
        "```rust\nfn main() {\n    println!(\"hi\");\n}\n```",
        "emoji 😀 👨‍👩‍👧‍👦 combining e\u{301} CJK 你好",
        "[broken](https://example.com/\nnext) [userinfo](https://user:pass@example.com)",
        &"*".repeat(128),
        &"])]([(".repeat(64),
    ];

    let mut corpus = seeds.iter().map(|text| text.to_string()).collect::<Vec<_>>();
    for index in 0..64 {
        corpus.push(generated_markdown_case(index));
    }
    corpus
}

fn generated_editor_corpus() -> Vec<String> {
    vec![
        "".to_string(),
        "plain text".to_string(),
        "a😀b".to_string(),
        "hello 👋🏽 world".to_string(),
        "Look 👨‍👩‍👧‍👦 here".to_string(),
        "CJK 你好 and accents Héllo".to_string(),
        "1. First\n2. Second".to_string(),
        "- item\n  - nested".to_string(),
        "Click <kbd>Enter</kbd>".to_string(),
        generated_markdown_case(99),
    ]
}

fn generated_markdown_case(seed: u64) -> String {
    let fragments = [
        "plain",
        "**bold**",
        "*italic*",
        "~~strike~~",
        "`code`",
        "[safe](HTTPS://Example.COM/Path)",
        "[bad](javascript:alert(1))",
        "<kbd>Enter</kbd>",
        "😀",
        "你好",
        "\n",
        "\n> quote",
        "\n1. item",
        "\n- item",
        "\n```txt\ncode\n```",
    ];

    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    let mut output = String::new();
    for _ in 0..24 {
        state = state.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
        output.push_str(fragments[(state as usize) % fragments.len()]);
        output.push(' ');
    }
    output
}

fn utf16_boundaries(text: &str) -> Vec<u32> {
    let mut offsets = vec![0];
    let mut current = 0;
    for ch in text.chars() {
        current += ch.len_utf16() as u32;
        offsets.push(current);
    }
    offsets
}
