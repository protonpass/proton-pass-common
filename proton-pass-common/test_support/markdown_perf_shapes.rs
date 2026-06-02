pub fn repeated_note(repetitions: usize) -> String {
    let mut text = String::new();
    for index in 0..repetitions {
        text.push_str("## Section ");
        text.push_str(&index.to_string());
        text.push_str("\n\n");
        text.push_str("- **Username**: user@example.com\n");
        text.push_str("- *URL*: https://example.com/login\n");
        text.push_str("- Note: preserve <kbd>Enter</kbd> as text.\n\n");
    }
    text
}

pub fn adversarial_but_in_budget() -> String {
    let mut text = String::new();
    for depth in 0..15 {
        text.push_str(&"  ".repeat(depth));
        text.push_str("- item\n");
    }
    text
}

pub fn link_heavy_note(count: usize) -> String {
    let mut text = String::new();
    for index in 0..count {
        text.push_str("[safe ");
        text.push_str(&index.to_string());
        text.push_str("](https://example.com/item/");
        text.push_str(&index.to_string());
        text.push_str(") [unsafe ");
        text.push_str(&index.to_string());
        text.push_str("](javascript:alert(1))\n");
    }
    text
}

pub fn inline_heavy_note(count: usize) -> String {
    let mut text = String::new();
    for index in 0..count {
        text.push_str("**b");
        text.push_str(&index.to_string());
        text.push_str("** *i");
        text.push_str(&index.to_string());
        text.push_str("* ~~s");
        text.push_str(&index.to_string());
        text.push_str("~~ `c");
        text.push_str(&index.to_string());
        text.push_str("` ");
    }
    text
}

pub fn deep_in_budget_structure() -> String {
    let mut text = String::new();
    for depth in 0..12 {
        text.push_str(&"> ".repeat(depth));
        text.push_str("quote\n");
    }
    text.push('\n');
    for depth in 0..12 {
        text.push_str(&"  ".repeat(depth));
        text.push_str("- nested item\n");
    }
    text
}

pub fn large_code_block_note(bytes: usize) -> String {
    let mut text = String::from("```text\n");
    text.push_str(&"a".repeat(bytes));
    text.push_str("\n```");
    text
}
