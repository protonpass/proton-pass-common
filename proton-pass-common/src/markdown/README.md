# Markdown Editor

A high-performance, CommonMark-compliant markdown editor with rendering and editing capabilities.

## Features

- **CommonMark Rendering**: Parse and render markdown text to styled spans
- **Editing Operations**: Apply formatting (bold, italic, strikethrough, headers, blockquotes) and manage lists
- **Undo/Redo**: Full undo/redo support with configurable history depth
- **Unicode-Aware**: Proper handling of emojis, grapheme clusters, and multi-byte characters
- **Stateful**: Single source of truth with efficient state management
- **Cross-Platform**: Exposed to mobile (via uniffi) and web (via wasm-bindgen)

## Core Operations

### Inline Formatting
- **Bold**: `**text**`
- **Italic**: `*text*`
- **Strikethrough**: `~~text~~`
- **Code**: `` `code` ``

### Block Formatting
- **Headers**: `# H1` through `###### H6`
- **Blockquote**: `> quote text`
- **Code Blocks**: ` ``` code ``` `

### Lists
- **Unordered Lists**: `- item` or `* item`
- **Ordered Lists**: `1. item`, `2. item`
- **Nested Lists**: Indent with 2 spaces per level
- **Indent/Unindent**: Change nesting level of list items

## Usage

### Text Editing Integration

The editor provides methods to sync with native text inputs that handle their own editing:

```rust
use proton_pass_common::markdown::MarkdownEditor;

let mut editor = MarkdownEditor::new("".to_string());

// Method 1: Insert text at cursor (most common for typing)
editor.insert_text("Hello").unwrap();
editor.insert_text(" world").unwrap();
assert_eq!(editor.get_text(), "Hello world");

// Method 2: Set entire text (useful when native input handles editing)
editor.set_text("Hello world".to_string());
editor.set_cursor(11).unwrap();

// All text operations support undo/redo
editor.undo(); // Revert to previous state

// Delete operations
editor.set_selection(0, 5).unwrap();
editor.delete_selection().unwrap();
assert_eq!(editor.get_text(), " world");

// Replace range
editor.replace_range(0, 6, "Hi!").unwrap();
assert_eq!(editor.get_text(), "Hi!");
```

**Integration Pattern:**

Most applications use native text inputs (UITextView, EditText, textarea) that handle their own text editing, IME, autocorrect, etc. The recommended pattern is:

1. **User types in native text input** → Native input updates its text
2. **On text change callback** → Call `editor.set_text(new_text)` to sync state
3. **User selects text and clicks format button** → Call `editor.set_selection()` then `editor.apply_operation()`
4. **Get formatted text** → Call `editor.get_text()` and update native input
5. **Render formatting** → Call `editor.render()` to get spans and apply to UI

### Basic Formatting Example

```rust
use proton_pass_common::markdown::{MarkdownEditor, Operation};

// Create an editor
let mut editor = MarkdownEditor::new("Hello world".to_string());

// Apply bold to a selection
editor.set_selection(0, 5).unwrap();
editor.apply_operation(Operation::Bold).unwrap();
assert_eq!(editor.get_text(), "**Hello** world");

// Undo
editor.undo();
assert_eq!(editor.get_text(), "Hello world");

// Redo
editor.redo();
assert_eq!(editor.get_text(), "**Hello** world");
```

### Rendering

```rust
use proton_pass_common::markdown::{MarkdownEditor, SpanStyle};

let editor = MarkdownEditor::new("**bold** and *italic*".to_string());
let spans = editor.render();

for span in spans {
    match span.style {
        SpanStyle::Bold => println!("Bold text from {} to {}", span.start, span.end),
        SpanStyle::Italic => println!("Italic text from {} to {}", span.start, span.end),
        _ => {}
    }
}
```

### Working with Lists

```rust
use proton_pass_common::markdown::{MarkdownEditor, Operation};

let mut editor = MarkdownEditor::new("Item 1\nItem 2\nItem 3".to_string());

// Create an unordered list
editor.set_selection(0, editor.get_text().len() as u32).unwrap();
editor.apply_operation(Operation::CreateUnorderedList).unwrap();
// Result: "- Item 1\n- Item 2\n- Item 3"

// Indent first item
editor.set_cursor(0).unwrap();
editor.apply_operation(Operation::IndentList).unwrap();
// Result: "  - Item 1\n- Item 2\n- Item 3"

// Unindent
editor.apply_operation(Operation::UnindentList).unwrap();
// Result: "- Item 1\n- Item 2\n- Item 3"
```

### Headers

```rust
use proton_pass_common::markdown::{MarkdownEditor, Operation};

let mut editor = MarkdownEditor::new("My Title".to_string());

// Apply H1
editor.set_cursor(4).unwrap();
editor.apply_operation(Operation::Header(1)).unwrap();
assert_eq!(editor.get_text(), "# My Title");

// Change to H2
editor.apply_operation(Operation::Header(2)).unwrap();
assert_eq!(editor.get_text(), "## My Title");

// Toggle off (apply same level again)
editor.apply_operation(Operation::Header(2)).unwrap();
assert_eq!(editor.get_text(), "My Title");
```

## Mobile Bindings (uniffi)

The markdown editor is exposed to mobile platforms (Android/iOS) via uniffi:

### Android (Kotlin) - Text Editing Integration

```kotlin
import android.text.Editable
import android.text.TextWatcher
import android.widget.EditText

// Typical integration pattern
class MarkdownEditText(context: Context) : AppCompatEditText(context) {
    private val editor = MarkdownEditor("")
    
    init {
        // Sync text changes from EditText to MarkdownEditor
        addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) {
                // Sync the entire text to the editor
                editor.setText(s.toString())
                
                // Optional: Update formatting spans
                updateFormatting()
            }
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })
    }
    
    fun applyBold() {
        val start = selectionStart.toUInt()
        val end = selectionEnd.toUInt()
        
        // Set selection in editor
        editor.setSelection(start, end)
        
        // Apply formatting
        editor.applyOperation(MarkdownOperation.BOLD)
        
        // Update EditText with formatted text
        setText(editor.toSpannableString())
        setSelection(editor.getCursor().toInt())
    }
    
    private fun updateFormatting() {
        // Render and apply spans without changing text
        val currentText = text.toString()
        val spanned = editor.toSpannableString()
        
        // Only update if text matches (avoid loops)
        if (currentText == spanned.toString()) {
            setText(spanned, BufferType.SPANNABLE)
            setSelection(editor.getCursor().toInt())
        }
    }
}

// Text editing methods
val editor = MarkdownEditor("Hello")

// User types more text
editor.insertText(" world")
println(editor.getText()) // "Hello world"

// Set entire text (when EditText changes)
editor.setText("Hello world from native input")
editor.setCursor(30u)

// Delete operations
editor.setSelection(0u, 5u)
editor.deleteSelection() // Deletes "Hello"

// Replace text
editor.replaceRange(0u, 6u, "Hi")

// Convert to SpannableString for TextView
fun MarkdownEditor.toSpannableString(): SpannableString {
    val text = getText()
    val spannable = SpannableString(text)
    val spans = render()
    
    for (span in spans) {
        val start = span.start.toInt()
        val end = span.end.toInt()
        
        val styleSpan = when (span.style) {
            MarkdownSpanStyle.BOLD -> 
                StyleSpan(android.graphics.Typeface.BOLD)
            
            MarkdownSpanStyle.ITALIC -> 
                StyleSpan(android.graphics.Typeface.ITALIC)
            
            MarkdownSpanStyle.STRIKETHROUGH -> 
                StrikethroughSpan()
            
            MarkdownSpanStyle.HEADER1 -> 
                RelativeSizeSpan(2.0f)
            
            MarkdownSpanStyle.HEADER2 -> 
                RelativeSizeSpan(1.75f)
            
            MarkdownSpanStyle.HEADER3 -> 
                RelativeSizeSpan(1.5f)
            
            MarkdownSpanStyle.CODE -> 
                TypefaceSpan("monospace")
            
            MarkdownSpanStyle.LINK -> {
                span.url?.let { URLSpan(it) }
            }
            
            MarkdownSpanStyle.BLOCKQUOTE -> {
                // Apply a quote bar (custom span or ForegroundColorSpan)
                ForegroundColorSpan(Color.GRAY)
            }
            
            else -> null
        }
        
        styleSpan?.let {
            spannable.setSpan(it, start, end, SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
    }
    
    return spannable
}

// Convert to AnnotatedString for Jetpack Compose
fun MarkdownEditor.toAnnotatedString(): AnnotatedString {
    val text = getText()
    val builder = AnnotatedString.Builder(text)
    val spans = render()
    
    for (span in spans) {
        val start = span.start.toInt()
        val end = span.end.toInt()
        
        when (span.style) {
            MarkdownSpanStyle.BOLD -> 
                builder.addStyle(SpanStyle(fontWeight = FontWeight.Bold), start, end)
            
            MarkdownSpanStyle.ITALIC -> 
                builder.addStyle(SpanStyle(fontStyle = FontStyle.Italic), start, end)
            
            MarkdownSpanStyle.STRIKETHROUGH -> 
                builder.addStyle(SpanStyle(textDecoration = TextDecoration.LineThrough), start, end)
            
            MarkdownSpanStyle.HEADER1 -> 
                builder.addStyle(SpanStyle(fontSize = 32.sp, fontWeight = FontWeight.Bold), start, end)
            
            MarkdownSpanStyle.HEADER2 -> 
                builder.addStyle(SpanStyle(fontSize = 28.sp, fontWeight = FontWeight.Bold), start, end)
            
            MarkdownSpanStyle.CODE -> 
                builder.addStyle(SpanStyle(fontFamily = FontFamily.Monospace, background = Color.LightGray), start, end)
            
            MarkdownSpanStyle.LINK -> {
                span.url?.let { url ->
                    builder.addStyle(SpanStyle(color = Color.Blue, textDecoration = TextDecoration.Underline), start, end)
                    builder.addStringAnnotation("URL", url, start, end)
                }
            }
            
            MarkdownSpanStyle.BLOCKQUOTE -> 
                builder.addStyle(SpanStyle(color = Color.Gray, fontStyle = FontStyle.Italic), start, end)
            
            else -> { /* Handle other styles */ }
        }
    }
    
    return builder.toAnnotatedString()
}

// Usage in Compose
@Composable
fun MarkdownText(editor: MarkdownEditor) {
    val annotatedString = remember(editor.getText()) {
        editor.toAnnotatedString()
    }
    
    ClickableText(
        text = annotatedString,
        onClick = { offset ->
            annotatedString.getStringAnnotations("URL", offset, offset)
                .firstOrNull()?.let { annotation ->
                    // Open URL
                }
        }
    )
}
```

### iOS (Swift) - Text Editing Integration

```swift
import UIKit

// Typical integration pattern
class MarkdownTextView: UITextView, UITextViewDelegate {
    private let editor: MarkdownEditor
    
    init() {
        self.editor = MarkdownEditor(text: "")
        super.init(frame: .zero, textContainer: nil)
        self.delegate = self
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    // Sync text changes from UITextView to MarkdownEditor
    func textViewDidChange(_ textView: UITextView) {
        // Sync the entire text to the editor
        editor.setText(text: textView.text ?? "")
        
        // Optional: Update formatting
        updateFormatting()
    }
    
    func applyBold() {
        let range = selectedRange
        let start = UInt32(range.location)
        let end = UInt32(range.location + range.length)
        
        // Set selection in editor
        try? editor.setSelection(start: start, end: end)
        
        // Apply formatting
        try? editor.applyOperation(operation: .bold)
        
        // Update UITextView with formatted text
        attributedText = editor.toAttributedString()
        selectedRange = NSRange(location: Int(editor.getCursor()), length: 0)
    }
    
    private func updateFormatting() {
        // Render and apply formatting without changing text
        let currentText = text ?? ""
        let attributed = editor.toAttributedString()
        
        // Only update if text matches (avoid loops)
        if currentText == attributed.string {
            let cursorPosition = selectedRange.location
            attributedText = attributed
            selectedRange = NSRange(location: cursorPosition, length: 0)
        }
    }
}

// Text editing methods
let editor = MarkdownEditor(text: "Hello")

// User types more text
try editor.insertText(text: " world")
print(editor.getText()) // "Hello world"

// Set entire text (when UITextView changes)
editor.setText(text: "Hello world from native input")
try editor.setCursor(position: 30)

// Delete operations
try editor.setSelection(start: 0, end: 5)
try editor.deleteSelection() // Deletes "Hello"

// Replace text
try editor.replaceRange(start: 0, end: 6, text: "Hi")

// Convert to NSAttributedString for UIKit
extension MarkdownEditor {
    func toAttributedString() -> NSAttributedString {
        let text = getText()
        let attributedString = NSMutableAttributedString(string: text)
        let spans = render()
        
        for span in spans {
            let start = Int(span.start)
            let length = Int(span.end - span.start)
            let range = NSRange(location: start, length: length)
            
            switch span.style {
            case .bold:
                attributedString.addAttribute(
                    .font,
                    value: UIFont.boldSystemFont(ofSize: 16),
                    range: range
                )
                
            case .italic:
                attributedString.addAttribute(
                    .font,
                    value: UIFont.italicSystemFont(ofSize: 16),
                    range: range
                )
                
            case .strikethrough:
                attributedString.addAttribute(
                    .strikethroughStyle,
                    value: NSUnderlineStyle.single.rawValue,
                    range: range
                )
                
            case .header1:
                attributedString.addAttribute(
                    .font,
                    value: UIFont.boldSystemFont(ofSize: 32),
                    range: range
                )
                
            case .header2:
                attributedString.addAttribute(
                    .font,
                    value: UIFont.boldSystemFont(ofSize: 28),
                    range: range
                )
                
            case .header3:
                attributedString.addAttribute(
                    .font,
                    value: UIFont.boldSystemFont(ofSize: 24),
                    range: range
                )
                
            case .code:
                attributedString.addAttribute(
                    .font,
                    value: UIFont.monospacedSystemFont(ofSize: 14, weight: .regular),
                    range: range
                )
                attributedString.addAttribute(
                    .backgroundColor,
                    value: UIColor.systemGray6,
                    range: range
                )
                
            case .link:
                if let url = span.url {
                    attributedString.addAttribute(
                        .link,
                        value: url,
                        range: range
                    )
                    attributedString.addAttribute(
                        .foregroundColor,
                        value: UIColor.systemBlue,
                        range: range
                    )
                }
                
            case .blockquote:
                attributedString.addAttribute(
                    .foregroundColor,
                    value: UIColor.systemGray,
                    range: range
                )
                attributedString.addAttribute(
                    .font,
                    value: UIFont.italicSystemFont(ofSize: 16),
                    range: range
                )
                
            default:
                break
            }
        }
        
        return attributedString
    }
}

// Convert to AttributedString for SwiftUI
extension MarkdownEditor {
    func toSwiftUIAttributedString() -> AttributedString {
        let text = getText()
        var attributedString = AttributedString(text)
        let spans = render()
        
        for span in spans {
            let startIndex = attributedString.index(attributedString.startIndex, offsetBy: Int(span.start))
            let endIndex = attributedString.index(attributedString.startIndex, offsetBy: Int(span.end))
            let range = startIndex..<endIndex
            
            switch span.style {
            case .bold:
                attributedString[range].font = .boldSystemFont(ofSize: 16)
                
            case .italic:
                attributedString[range].font = .italicSystemFont(ofSize: 16)
                
            case .strikethrough:
                attributedString[range].strikethroughStyle = .single
                
            case .header1:
                attributedString[range].font = .boldSystemFont(ofSize: 32)
                
            case .header2:
                attributedString[range].font = .boldSystemFont(ofSize: 28)
                
            case .header3:
                attributedString[range].font = .boldSystemFont(ofSize: 24)
                
            case .code:
                attributedString[range].font = .monospacedSystemFont(ofSize: 14, weight: .regular)
                attributedString[range].backgroundColor = .systemGray6
                
            case .link:
                if let urlString = span.url, let url = URL(string: urlString) {
                    attributedString[range].link = url
                    attributedString[range].foregroundColor = .blue
                    attributedString[range].underlineStyle = .single
                }
                
            case .blockquote:
                attributedString[range].foregroundColor = .gray
                attributedString[range].font = .italicSystemFont(ofSize: 16)
                
            default:
                break
            }
        }
        
        return attributedString
    }
}

// Usage in SwiftUI
struct MarkdownView: View {
    let editor: MarkdownEditor
    
    var body: some View {
        Text(editor.toSwiftUIAttributedString())
    }
}

// Usage in UIKit
class MarkdownViewController: UIViewController {
    let editor = MarkdownEditor(text: "**Bold** and *italic* text")
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let textView = UITextView()
        textView.attributedText = editor.toAttributedString()
        textView.isEditable = false
        view.addSubview(textView)
    }
}
```

## Web Bindings (WASM)

The markdown editor is exposed to web via wasm-bindgen.

### Text Editing Integration

```typescript
import { MarkdownEditor, WasmMarkdownOperation } from './pkg/markdown';

// Typical integration pattern with a textarea
class MarkdownTextarea {
    private editor: MarkdownEditor;
    private textarea: HTMLTextAreaElement;
    
    constructor(textarea: HTMLTextAreaElement) {
        this.textarea = textarea;
        this.editor = new MarkdownEditor(textarea.value);
        
        // Sync text changes from textarea to editor
        textarea.addEventListener('input', () => {
            this.editor.setText(textarea.value);
            this.editor.setCursor(textarea.selectionStart);
        });
        
        // Sync cursor/selection changes
        textarea.addEventListener('selectionchange', () => {
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            
            if (start === end) {
                this.editor.setCursor(start);
            } else {
                this.editor.setSelection(start, end);
            }
        });
    }
    
    applyBold() {
        const start = this.textarea.selectionStart;
        const end = this.textarea.selectionEnd;
        
        // Set selection in editor
        this.editor.setSelection(start, end);
        
        // Apply formatting
        this.editor.applyOperation(WasmMarkdownOperation.Bold);
        
        // Update textarea with formatted text
        this.textarea.value = this.editor.getText();
        this.textarea.selectionStart = this.editor.getCursor();
        this.textarea.selectionEnd = this.editor.getCursor();
    }
    
    undo() {
        if (this.editor.undo()) {
            this.textarea.value = this.editor.getText();
        }
    }
    
    redo() {
        if (this.editor.redo()) {
            this.textarea.value = this.editor.getText();
        }
    }
}

// Text editing methods
const editor = new MarkdownEditor("Hello");

// User types more text
editor.insertText(" world");
console.log(editor.getText()); // "Hello world"

// Set entire text (when textarea changes)
editor.setText("Hello world from native input");
editor.setCursor(30);

// Delete operations
editor.setSelection(0, 5);
editor.deleteSelection(); // Deletes "Hello"

// Replace text
editor.replaceRange(0, 6, "Hi");
```

### Basic Formatting Example

```typescript
import { MarkdownEditor, WasmMarkdownOperation, WasmMarkdownSpanStyle } from './pkg/markdown';

// Create an editor
const editor = new MarkdownEditor("Hello world");

// Apply formatting
editor.setSelection(0, 5);
editor.applyOperation("bold");
console.log(editor.getText()); // "**Hello** world"

// Undo/redo
editor.undo();
console.log(editor.getText()); // "Hello world"
editor.redo();
console.log(editor.getText()); // "**Hello** world"

// Render to HTML (web-only convenience method)
const html = editor.renderToHtml();
console.log(html); // "<p><strong>Hello</strong> world</p>\n"

// Or render to spans for custom rendering
const spans = editor.render();
for (const span of spans) {
    if (span.style === "bold") {
        // Apply bold styling to text[span.start..span.end]
    }
}

// Smart newline insertion with list continuation
editor.setText("1. First item");
editor.setCursor(13);
editor.insertNewline();
console.log(editor.getText()); // "1. First item\n2. "
```

## Architecture

### Core Design

- **Stateful Editor**: Maintains text, cursor position, selection, and undo/redo stacks
- **Functional Core**: Pure functions for operations (operations.rs, list_operations.rs)
- **Imperative Shell**: Stateful wrapper that manages history (editor.rs)

### Components

1. **editor.rs**: Main `MarkdownEditor` struct with state management
2. **renderer.rs**: CommonMark parser integration for rendering
3. **operations.rs**: Inline formatting operations (bold, italic, etc.)
4. **list_operations.rs**: List creation and manipulation
5. **cursor.rs**: Unicode-aware cursor and selection utilities
6. **undo.rs**: Undo/redo stack implementation

### HTML Rendering (Web Only)

For web applications, a convenient `renderToHtml()` method is available that directly converts markdown to HTML:

```typescript
const editor = new MarkdownEditor("# Title\n\n**Bold** text");
const html = editor.renderToHtml();
// Returns: "<h1>Title</h1>\n<p><strong>Bold</strong> text</p>\n"
```

This uses the battle-tested `pulldown-cmark` HTML renderer with support for:
- All CommonMark features
- Strikethrough (`~~text~~`)
- Tables
- Task lists
- Footnotes

### Structured Rendering

The renderer can also return structured spans for custom rendering:

```rust
pub struct StyledSpan {
    pub start: u32,  // Byte offset
    pub end: u32,    // Byte offset
    pub style: SpanStyle,
}

pub enum SpanStyle {
    Bold,
    Italic,
    Strikethrough,
    Header(u8),
    Code,
    Link { url: String },
    OrderedListItem { level: u8, number: u32 },
    UnorderedListItem { level: u8 },
    // ...
}
```

This approach allows easy conversion to:
- **Android**: Spannable / SpannableString
- **iOS**: AttributedString
- **Web**: HTML or custom rendering

## Testing

The module includes comprehensive tests:

- **Unit tests**: Each module has its own test suite
- **Integration tests**: Full workflows in `tests/markdown_editor.rs`
- **Edge case tests**: Unicode, emojis, boundaries, multiline
- **Web E2E tests**: TypeScript tests in `proton-pass-web/test/`

Run tests:
```bash
# Core library tests
cargo test --package proton-pass-common markdown

# Integration tests
cargo test --package proton-pass-common --test markdown_editor

# Web tests (requires building WASM first)
cd proton-pass-web
make web-test
```

## Performance Considerations

- **Efficient State Storage**: Text is stored as `String` with copy-on-write semantics
- **Limited Undo Stack**: Configurable max depth (default: 100 operations)
- **Lazy Rendering**: Spans are only computed when `render()` is called
- **Unicode-Aware**: Uses `unicode-segmentation` for correct grapheme handling

## Edge Cases Handled

- **Emoji Support**: Full support for complex emojis with skin tone modifiers
- **Word Boundaries**: Intelligent word detection for cursor operations
- **Empty Text**: Graceful handling of empty strings and selections
- **Line Boundaries**: Proper handling of operations at line starts/ends
- **Nested Formatting**: Support for overlapping and nested markdown syntax

