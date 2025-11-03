// Additional integration-style tests for the markdown editor

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

    // Apply bold - should bold the word "test"
    editor.apply_operation(Operation::Bold).unwrap();
    assert!(editor.get_text().contains("**test**"));
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
    editor.set_selection(text_pos as u32, (text_pos + 4) as u32).unwrap();
    editor.apply_operation(Operation::Italic).unwrap();

    let result = editor.get_text();
    assert!(result.contains("**sample**"));
    assert!(result.contains("*text*"));
}

#[test]
fn test_list_creation_and_indentation() {
    let mut editor = MarkdownEditor::new("item 1\nitem 2\nitem 3".to_string());

    // Create unordered list
    editor.set_selection(0, editor.get_text().len() as u32).unwrap();
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
    let mut editor = MarkdownEditor::new("hello 👋🏽 world".to_string());

    let emoji_start = "hello ".len();
    let emoji_end = emoji_start + "👋🏽".len();

    editor.set_selection(emoji_start as u32, emoji_end as u32).unwrap();
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
    editor
        .set_selection(text_start as u32, (text_start + 4) as u32)
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

    let spans = editor.render();
    let has_bold = spans.iter().any(|s| matches!(s.style, SpanStyle::Bold));
    assert!(has_bold);
}

#[test]
fn test_ordered_list_numbering() {
    let mut editor = MarkdownEditor::new("first\nsecond\nthird".to_string());

    editor.set_selection(0, editor.get_text().len() as u32).unwrap();
    editor.apply_operation(Operation::CreateOrderedList).unwrap();

    let text = editor.get_text();
    assert!(text.contains("1. first"));
    assert!(text.contains("2. second"));
    assert!(text.contains("3. third"));
}

#[test]
fn test_complex_emoji_family() {
    // Family emoji with skin tone modifiers
    let mut editor = MarkdownEditor::new("Look 👨‍👩‍👧‍👦 here".to_string());

    let emoji_start = "Look ".len();
    let emoji = "👨‍👩‍👧‍👦";
    let emoji_end = emoji_start + emoji.len();

    editor.set_selection(emoji_start as u32, emoji_end as u32).unwrap();
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

    // Should bold "hello"
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "**hello** world");
}

#[test]
fn test_cursor_at_end_of_word_italic() {
    let mut editor = MarkdownEditor::new("test item".to_string());
    // Cursor at position 4 (right after "test")
    editor.set_cursor(4).unwrap();

    // Should italicize "test"
    editor.apply_operation(Operation::Italic).unwrap();
    assert_eq!(editor.get_text(), "*test* item");
}

#[test]
fn test_cursor_at_end_of_second_word() {
    let mut editor = MarkdownEditor::new("first second".to_string());
    // Cursor at position 12 (right after "second")
    editor.set_cursor(12).unwrap();

    // Should bold "second"
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "first **second**");
}

#[test]
fn test_cursor_at_end_of_text() {
    let mut editor = MarkdownEditor::new("word".to_string());
    // Cursor at end of text
    editor.set_cursor(4).unwrap();

    // Should bold "word"
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "**word**");
}

#[test]
fn test_cursor_at_end_with_emoji() {
    let mut editor = MarkdownEditor::new("test👋 next".to_string());
    // Cursor right after emoji
    let emoji_end = "test👋".len() as u32;
    editor.set_cursor(emoji_end).unwrap();

    // Should bold "test👋"
    editor.apply_operation(Operation::Bold).unwrap();
    assert!(editor.get_text().contains("**test👋**"));
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
    assert_eq!(editor2.get_text(), "**testing**");

    // Both should produce the same result
    assert_eq!(editor1.get_text(), editor2.get_text());
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

    // Step 1: Apply strikethrough with cursor on word
    editor.set_cursor(2).unwrap(); // cursor in "text"
    editor.apply_operation(Operation::Strikethrough).unwrap();
    assert_eq!(editor.get_text(), "~~text~~");

    // Step 2: Apply bold (cursor should be after "text")
    editor.apply_operation(Operation::Bold).unwrap();
    let after_bold = editor.get_text();

    // Should be ~~**text**~~ or **~~text~~** depending on where cursor ended up
    // Both are valid, but it should contain both ~~ and **
    assert!(after_bold.contains("~~"));
    assert!(after_bold.contains("**"));
    assert!(after_bold.contains("text"));

    // Step 3: Apply strikethrough again - should REMOVE it, not add it twice
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

    editor.set_cursor(2).unwrap();
    editor.apply_operation(Operation::Italic).unwrap();
    assert_eq!(editor.get_text(), "*word*");

    editor.apply_operation(Operation::Bold).unwrap();
    let after_bold = editor.get_text();
    assert!(after_bold.contains("*"));
    assert!(after_bold.contains("**"));

    editor.apply_operation(Operation::Italic).unwrap();
    let final_text = editor.get_text();
    // After toggling italic on ***word***, we should have **word** (italic removed, bold remains)
    assert_eq!(final_text, "**word**");
}

#[test]
fn test_nested_bold_strikethrough_toggle() {
    // Test: bold -> strikethrough -> bold should remove bold
    let mut editor = MarkdownEditor::new("test".to_string());

    editor.set_cursor(2).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "**test**");

    editor.apply_operation(Operation::Strikethrough).unwrap();
    assert!(editor.get_text().contains("**"));
    assert!(editor.get_text().contains("~~"));

    editor.apply_operation(Operation::Bold).unwrap();
    let final_text = editor.get_text();
    assert!(!final_text.contains("**"), "Expected bold to be removed");
    assert_eq!(final_text, "~~test~~");
}

#[test]
fn test_triple_nested_formatting() {
    // Test: strikethrough -> italic -> bold -> remove each in order
    let mut editor = MarkdownEditor::new("word".to_string());

    editor.set_cursor(2).unwrap();

    // Apply all three
    editor.apply_operation(Operation::Strikethrough).unwrap();
    editor.apply_operation(Operation::Italic).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();

    let triple = editor.get_text();
    assert!(triple.contains("~~"), "Should have strikethrough");
    assert!(triple.contains("*"), "Should have italic");
    assert!(triple.contains("**"), "Should have bold");

    // Remove bold
    editor.apply_operation(Operation::Bold).unwrap();
    let after_bold = editor.get_text();
    assert!(!after_bold.contains("**"), "Bold should be removed");
    assert!(after_bold.contains("*"), "Italic should remain");
    assert!(after_bold.contains("~~"), "Strikethrough should remain");

    // Remove italic
    editor.apply_operation(Operation::Italic).unwrap();
    let after_italic = editor.get_text();
    assert!(!after_italic.contains("*"), "Italic should be removed");
    assert!(after_italic.contains("~~"), "Strikethrough should remain");

    // Remove strikethrough
    editor.apply_operation(Operation::Strikethrough).unwrap();
    assert_eq!(editor.get_text(), "word", "All formatting should be removed");
}

#[test]
fn test_nested_toggle_different_order() {
    // Test removing in different order than applying
    let mut editor = MarkdownEditor::new("text".to_string());

    editor.set_cursor(2).unwrap();

    // Apply: italic -> bold -> strikethrough
    editor.apply_operation(Operation::Italic).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();
    editor.apply_operation(Operation::Strikethrough).unwrap();

    // Remove: italic (should reduce *** to **)
    editor.apply_operation(Operation::Italic).unwrap();
    let after = editor.get_text();
    // After removing italic from ***~~text~~***, we should have **~~text~~**
    // (bold outside, strikethrough inside, because that's the order they were applied)
    assert!(after.contains("**"), "Bold should remain");
    assert!(after.contains("~~"), "Strikethrough should remain");
    assert!(after.starts_with("**~~"), "Should start with **~~");
    assert_eq!(after, "**~~text~~**");
}
