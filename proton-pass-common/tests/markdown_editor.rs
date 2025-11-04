use proton_pass_common::markdown::{MarkdownEditor, Operation, SpanStyle};

#[test]
fn test_complete_workflow() {
    let mut editor = MarkdownEditor::new("My Document\n\nThis is a paragraph.".to_string());

    // Make title a header
    editor.set_cursor(5).unwrap();
    editor.apply_operation(Operation::Header(1)).unwrap();
    assert!(editor.get_text().starts_with("# My Document"));

    // Bold "paragraph"
    let para_start = editor.get_text().find("paragraph").unwrap();
    editor
        .set_selection(para_start as u32, (para_start + 9) as u32)
        .unwrap();
    editor.apply_operation(Operation::Bold).unwrap();
    assert!(editor.get_text().contains("**paragraph**"));

    // Undo bold
    assert!(editor.undo());
    assert!(!editor.get_text().contains("**paragraph**"));

    // Redo bold
    assert!(editor.redo());
    assert!(editor.get_text().contains("**paragraph**"));
}

#[test]
fn test_list_workflow() {
    let mut editor = MarkdownEditor::new("Apple\nBanana\nCherry".to_string());

    // Create unordered list
    editor.set_selection(0, editor.get_text().len() as u32).unwrap();
    editor.apply_operation(Operation::CreateUnorderedList).unwrap();

    assert!(editor.get_text().contains("- Apple"));
    assert!(editor.get_text().contains("- Banana"));
    assert!(editor.get_text().contains("- Cherry"));

    // Indent first item
    editor.set_cursor(0).unwrap();
    editor.apply_operation(Operation::IndentList).unwrap();
    assert!(editor.get_text().starts_with("  - Apple"));

    // Indent again
    editor.apply_operation(Operation::IndentList).unwrap();
    assert!(editor.get_text().starts_with("    - Apple"));

    // Unindent
    editor.apply_operation(Operation::UnindentList).unwrap();
    assert!(editor.get_text().starts_with("  - Apple"));

    // Convert to ordered list
    editor.set_selection(0, editor.get_text().len() as u32).unwrap();

    // Toggle off unordered
    editor.apply_operation(Operation::CreateUnorderedList).unwrap();

    // Create ordered
    editor.set_selection(0, editor.get_text().len() as u32).unwrap();
    editor.apply_operation(Operation::CreateOrderedList).unwrap();

    assert!(editor.get_text().contains("1. "));
    assert!(editor.get_text().contains("2. "));
    assert!(editor.get_text().contains("3. "));
}

#[test]
fn test_combined_formatting() {
    let mut editor = MarkdownEditor::new("important text here".to_string());

    // Bold "important"
    editor.set_selection(0, 9).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();

    // Italic "text"
    let text_pos = editor.get_text().find("text").unwrap();
    editor.set_selection(text_pos as u32, (text_pos + 4) as u32).unwrap();
    editor.apply_operation(Operation::Italic).unwrap();

    // Strikethrough "here"
    let here_pos = editor.get_text().find("here").unwrap();
    editor.set_selection(here_pos as u32, (here_pos + 4) as u32).unwrap();
    editor.apply_operation(Operation::Strikethrough).unwrap();

    let text = editor.get_text();
    assert!(text.contains("**important**"));
    assert!(text.contains("*text*"));
    assert!(text.contains("~~here~~"));
}

#[test]
fn test_render_spans() {
    let editor = MarkdownEditor::new("**bold** and *italic*".to_string());

    let spans = editor.render();

    let bold_spans: Vec<_> = spans.iter().filter(|s| matches!(s.style, SpanStyle::Bold)).collect();
    let italic_spans: Vec<_> = spans.iter().filter(|s| matches!(s.style, SpanStyle::Italic)).collect();

    assert_eq!(bold_spans.len(), 1);
    assert_eq!(italic_spans.len(), 1);

    // Verify positions
    let text = editor.get_text();
    let bold_span = bold_spans[0];
    assert_eq!(&text[bold_span.start as usize..bold_span.end as usize], "**bold**");
}

#[test]
fn test_unicode_edge_cases() {
    // Test with various Unicode scenarios
    let test_cases = vec![
        ("Hello 👋", "emoji"),
        ("Test 👨‍👩‍👧‍👦 family", "family emoji"),
        ("Wave 👋🏽 skin", "emoji with skin tone"),
        ("Emoji 🏴󠁧󠁢󠁳󠁣󠁴󠁿 flag", "flag emoji"),
        ("Text with 日本語 characters", "Japanese"),
        ("Hebrew עברית text", "Hebrew"),
    ];

    for (text, description) in test_cases {
        let mut editor = MarkdownEditor::new(text.to_string());

        // Convert UTF-8 length to UTF-16 length for selection
        let utf16_len = text.encode_utf16().count() as u32;
        editor.set_selection(0, utf16_len).unwrap();

        // Should not panic
        let result = editor.apply_operation(Operation::Bold);
        assert!(result.is_ok(), "Failed on test case: {}", description);

        // Should contain formatting
        assert!(
            editor.get_text().contains("**"),
            "No formatting applied for: {}",
            description
        );
    }
}

#[test]
fn test_cursor_at_boundaries() {
    let mut editor = MarkdownEditor::new("hello world".to_string());

    // Cursor at start
    editor.set_cursor(0).unwrap();
    let result = editor.apply_operation(Operation::Bold);
    assert!(result.is_ok());

    // Cursor at end
    editor = MarkdownEditor::new("hello world".to_string());
    editor.set_cursor(11).unwrap();
    let result = editor.apply_operation(Operation::Bold);
    assert!(result.is_ok());

    // Cursor at word boundary
    editor = MarkdownEditor::new("hello world".to_string());
    editor.set_cursor(5).unwrap(); // At space
    let result = editor.apply_operation(Operation::Bold);
    assert!(result.is_ok());
}

#[test]
fn test_header_levels() {
    for level in 1..=6 {
        let mut editor = MarkdownEditor::new("Header".to_string());
        editor.set_cursor(3).unwrap();
        editor.apply_operation(Operation::Header(level)).unwrap();

        let expected_prefix = "#".repeat(level as usize) + " ";
        assert!(
            editor.get_text().starts_with(&expected_prefix),
            "Failed for level {}",
            level
        );
    }
}

#[test]
fn test_invalid_header_level() {
    let mut editor = MarkdownEditor::new("Text".to_string());
    editor.set_cursor(0).unwrap();

    let result = editor.apply_operation(Operation::Header(0));
    assert!(result.is_err());

    let result = editor.apply_operation(Operation::Header(7));
    assert!(result.is_err());
}

#[test]
fn test_undo_redo_limits() {
    let mut editor = MarkdownEditor::new("test".to_string());

    // Perform many operations
    for _ in 0..150 {
        editor.set_selection(0, 4).unwrap();
        editor.apply_operation(Operation::Bold).unwrap();
        editor.apply_operation(Operation::Bold).unwrap(); // Toggle off
    }

    // Undo should work but be limited to stack size (100)
    let mut undo_count = 0;
    while editor.undo() {
        undo_count += 1;
    }

    // Should have some limit
    assert!(undo_count <= 100);
}

#[test]
fn test_empty_and_whitespace() {
    // Empty string
    let mut editor = MarkdownEditor::new(String::new());
    let result = editor.apply_operation(Operation::Bold);
    assert!(result.is_ok());

    // Only whitespace
    let mut editor = MarkdownEditor::new("   \n  \n   ".to_string());
    editor.set_selection(0, editor.get_text().len() as u32).unwrap();
    let result = editor.apply_operation(Operation::Bold);
    assert!(result.is_ok());
}

#[test]
fn test_multiline_operations() {
    let mut editor = MarkdownEditor::new("Line 1\nLine 2\nLine 3".to_string());

    // Select across lines
    editor.set_selection(5, 15).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();

    assert!(editor.get_text().contains("**"));
}

#[test]
fn test_rendering_after_operations() {
    let mut editor = MarkdownEditor::new("Plain text".to_string());

    // Before any operations - no spans with formatting
    let spans_before = editor.render();
    let has_formatting_before = spans_before
        .iter()
        .any(|s| matches!(s.style, SpanStyle::Bold | SpanStyle::Italic));
    assert!(!has_formatting_before);

    // Apply bold
    editor.set_selection(0, 5).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();

    // After operations - should have spans
    let spans_after = editor.render();
    let has_bold = spans_after.iter().any(|s| matches!(s.style, SpanStyle::Bold));
    assert!(has_bold);
}

#[test]
fn test_word_boundary_detection() {
    let mut editor = MarkdownEditor::new("one two three".to_string());

    // Cursor in middle of "two"
    editor.set_cursor(5).unwrap(); // 't' in "two"
    editor.apply_operation(Operation::Bold).unwrap();

    // Should have bolded "two"
    assert!(editor.get_text().contains("**two**"));
    assert!(!editor.get_text().contains("**one**"));
    assert!(!editor.get_text().contains("**three**"));
}

#[test]
fn test_list_item_counting() {
    let mut editor = MarkdownEditor::new("A\nB\nC\nD\nE".to_string());

    editor.set_selection(0, editor.get_text().len() as u32).unwrap();
    editor.apply_operation(Operation::CreateOrderedList).unwrap();

    let text = editor.get_text();
    assert!(text.contains("1. A"));
    assert!(text.contains("2. B"));
    assert!(text.contains("3. C"));
    assert!(text.contains("4. D"));
    assert!(text.contains("5. E"));
}

#[test]
fn test_toggle_formatting() {
    let mut editor = MarkdownEditor::new("word".to_string());

    // Apply bold
    editor.set_selection(0, 4).unwrap();
    editor.apply_operation(Operation::Bold).unwrap();
    assert!(editor.get_text().contains("**word**"));

    // Toggle off bold
    editor.set_selection(2, 6).unwrap(); // Select the text inside **
    editor.apply_operation(Operation::Bold).unwrap();
    assert_eq!(editor.get_text(), "word");

    // Apply italic
    editor.set_selection(0, 4).unwrap();
    editor.apply_operation(Operation::Italic).unwrap();
    assert!(editor.get_text().contains("*word*"));
}
