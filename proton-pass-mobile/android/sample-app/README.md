# Proton Pass Markdown Sample App

A production-ready sample Android application demonstrating how to integrate the Rust-based Proton Pass markdown library into an Android app using Jetpack Compose.

## Features

### 🎨 Hybrid Markdown Editor
- **Live syntax highlighting** - See markdown syntax with visual styling in real-time
- **WYSIWYG-like experience** - Markdown markers are visible but styled for better readability
- **Smart undo/redo** - Batches keystrokes intelligently (saves on word boundaries or after 1s pause)
- **Scrollable editor** - Smooth scrolling for long documents

### ✨ Full Markdown Support
- **Bold** (`**text**`)
- *Italic* (`*text*`)
- ~~Strikethrough~~ (`~~text~~`)
- Headers (H1-H6) (`# text`)
- > Blockquotes (`> text`)
- Ordered and unordered lists
  - **List indentation** - Indent/unindent list items with arrow buttons
  - **Smart list continuation** - Pressing Enter in a list automatically creates a new item
  - **Auto-exit lists** - Pressing Enter on an empty list item exits the list
- Inline code and code blocks
- Links

### 🏗️ Architecture
- **MVVM pattern** with ViewMod

el and StateFlow
- **Jetpack Compose** UI with Material 3
- **Navigation Compose** for screen navigation
- **DataStore** for persistent storage
- **UniFFI** for Rust-Kotlin interoperability

## Project Structure

```
sample-app/
├── src/main/java/com/proton/pass/markdown/sample/
│   ├── MainActivity.kt              # App entry point
│   ├── MarkdownViewModel.kt         # Business logic and state management
│   ├── MarkdownStorage.kt           # Persistent storage with DataStore
│   ├── Navigation.kt                # Navigation setup
│   └── ui/
│       ├── screens/
│       │   ├── ViewScreen.kt        # Display rendered markdown
│       │   └── EditScreen.kt        # Hybrid markdown editor
│       └── theme/
│           ├── Theme.kt             # Material 3 theme
│           └── Type.kt              # Typography
└── build.gradle.kts                 # Dependencies and config
```

## Key Integration Points

### 1. ViewModel Integration

```kotlin
class MarkdownViewModel : AndroidViewModel {
    // Initialize the Rust editor
    private var editor: MarkdownEditor? = null

    init {
        editor = MarkdownEditor(initialContent)
    }

    // Update text without saving undo state (for typing)
    fun updateText(newText: String, cursorPos: Int) {
        editor?.let { ed ->
            ed.setText(newText)  // Syncs with native input
            ed.setCursor(bytePosition)

            // Smart undo batching
            if (isWordBoundary) {
                ed.saveUndoState()  // Save immediately
            } else {
                scheduleUndoSave()  // Save after delay
            }
        }
    }

    // Apply formatting operations
    fun applyOperation(operation: MarkdownOperation) {
        editor?.applyOperation(operation)  // Auto-saves undo state
    }
}
```

### 2. Hybrid Rendering

The `EditScreen` uses a `BasicTextField` with styled overlay:

```kotlin
@Composable
fun HybridMarkdownEditor(
    value: TextFieldValue,
    spans: List<MarkdownStyledSpan>,
    onValueChange: (TextFieldValue) -> Unit
) {
    // Build annotated string with styles
    val styledText = buildStyledText(value.text, spans)

    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        decorationBox = { innerTextField ->
            Box {
                // Styled overlay showing markdown with formatting
                Text(text = styledText)
                // Invisible text field for input
                innerTextField()
            }
        }
    )
}
```

### 3. Byte Offset Handling

The Rust library uses UTF-8 byte offsets, which must be converted to/from Kotlin's UTF-16 character offsets:

```kotlin
private fun byteOffsetToCharOffset(text: String, byteOffset: Int): Int {
    var charOffset = 0
    var currentBytes = 0

    while (charOffset < text.length && currentBytes < byteOffset) {
        val charBytes = text[charOffset].toString()
            .toByteArray(Charsets.UTF_8).size
        currentBytes += charBytes
        charOffset++
    }

    return charOffset
}
```

## Building and Running

### Prerequisites
- Android Studio Hedgehog (2023.1.1) or later
- Kotlin 2.1.0+
- Gradle 8.7+
- Android SDK 35 (target), minimum SDK 26

### Build Steps

1. **Build the Rust library** (if not already built):
   ```bash
   cd /path/to/proton-pass-common
   make android
   ```

2. **Open in Android Studio**:
   ```bash
   cd proton-pass-mobile/android
   # Open this directory in Android Studio
   ```

3. **Sync Gradle** and **Run the app**

The app will run on API 26+ devices/emulators.

## Dependencies

Key dependencies used in this sample:

```kotlin
// Jetpack Compose BOM
implementation(platform("androidx.compose:compose-bom:2024.10.01"))

// Compose UI
implementation("androidx.compose.ui:ui")
implementation("androidx.compose.material3:material3")
implementation("androidx.compose.foundation:foundation")

// Navigation
implementation("androidx.navigation:navigation-compose:2.8.4")

// ViewModel
implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")

// DataStore
implementation("androidx.datastore:datastore-preferences:1.1.1")

// Local library
implementation(project(":lib"))
```

## Usage Examples

### Applying Formatting

```kotlin
// In your composable or ViewModel
viewModel.applyOperation(MarkdownOperation.BOLD)
viewModel.applyOperation(MarkdownOperation.HEADER1)
viewModel.applyOperation(MarkdownOperation.CREATE_UNORDERED_LIST)
viewModel.applyOperation(MarkdownOperation.INDENT_LIST)
viewModel.applyOperation(MarkdownOperation.UNINDENT_LIST)
```

### Smart List Continuation

```kotlin
// When user presses Enter in a list, automatically continue the list
viewModel.insertNewline()  // Auto-detects list context and continues or exits
```

### Undo/Redo

```kotlin
if (viewModel.canUndo) {
    viewModel.undo()
}

if (viewModel.canRedo) {
    viewModel.redo()
}
```

### Saving Content

```kotlin
// Content is auto-saved when navigating back
// Or manually:
viewModel.saveContent()
```

### Getting Rendered Spans

```kotlin
val spans by viewModel.styledSpans.collectAsStateWithLifecycle()
// Use spans to style the text in Compose
```

## Best Practices Demonstrated

1. **State Management**: Using `StateFlow` for reactive UI updates
2. **Smart Undo Batching**: Prevents creating an undo state for every keystroke
3. **UTF-8 Handling**: Proper conversion between Rust byte offsets and Kotlin char offsets
4. **Material 3**: Modern Android UI design
5. **Edge-to-Edge**: Full-screen immersive experience
6. **Error Handling**: Graceful handling of library exceptions
7. **Memory Efficiency**: Using `Arc<String>` in Rust to avoid copying text

## Performance Considerations

- **Undo batching** reduces memory usage and improves performance
- **Arc<String>** sharing in Rust minimizes string copies
- **Efficient rendering** with annotated strings in Compose
- **Coroutines** for async storage operations

## Customization

### Changing Colors

Edit `ui/theme/Theme.kt` to customize the color scheme:

```kotlin
private val ProtonPurple = Color(0xFF6D4AFF)  // Change this
```

### Adding More Operations

Add new formatting buttons in `EditScreen.kt`:

```kotlin
FilledTonalButton(
    onClick = { onOperation(MarkdownOperation.YOUR_OPERATION) }
) {
    Text("Label")
}
```

### Storage Backend

Replace `MarkdownStorage.kt` with your preferred storage:
- Room database for complex queries
- Encrypted storage for sensitive data
- Cloud sync integration

## Troubleshooting

### Build Errors

**Issue**: Cannot find `MarkdownEditor` class
- **Solution**: Ensure you've built the Rust library with `make android`

**Issue**: UniFFI binding errors
- **Solution**: Clean and rebuild: `./gradlew clean assembleDebug`

### Runtime Issues

**Issue**: Crash on text input
- **Solution**: Check byte offset conversions are correct

**Issue**: Undo not working
- **Solution**: Ensure `saveUndoState()` is called appropriately

## License

This sample app is part of the Proton Pass Common Rust library.

## Support

For issues or questions:
- Check the main repository README
- Review the Rust library documentation
- Examine the web sample for comparison

---

**Note**: This is a sample app for demonstration purposes. For production use, consider adding:
- Proper error handling and user feedback
- Accessibility features
- Analytics/crash reporting
- More comprehensive tests
- Multi-document support
- Export/import functionality
