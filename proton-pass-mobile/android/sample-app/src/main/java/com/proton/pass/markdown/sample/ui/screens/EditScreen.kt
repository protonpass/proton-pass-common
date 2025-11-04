package com.proton.pass.markdown.sample.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Redo
import androidx.compose.material.icons.automirrored.filled.Undo
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.foundation.text.selection.LocalTextSelectionColors
import androidx.compose.foundation.text.selection.TextSelectionColors
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalTextToolbar
import androidx.compose.ui.platform.TextToolbar
import androidx.compose.ui.platform.TextToolbarStatus
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupProperties
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.proton.pass.markdown.sample.MarkdownViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import proton.android.pass.commonrust.MarkdownOperation
import proton.android.pass.commonrust.MarkdownSpanStyle
import proton.android.pass.commonrust.MarkdownStyledSpan

/**
 * Edit screen with hybrid markdown rendering.
 * Shows markdown syntax with live styling, similar to the web version.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditScreen(
    viewModel: MarkdownViewModel,
    onBack: () -> Unit
) {
    val text by viewModel.text.collectAsStateWithLifecycle()
    val spans by viewModel.styledSpans.collectAsStateWithLifecycle()
    val cursorPosition by viewModel.cursorPosition.collectAsStateWithLifecycle()
    val selection by viewModel.selection.collectAsStateWithLifecycle()
    val canUndo by remember { derivedStateOf { viewModel.canUndo } }
    val canRedo by remember { derivedStateOf { viewModel.canRedo } }

    var textFieldValue by remember { mutableStateOf(TextFieldValue(text)) }

    // Track if we're in the middle of a user gesture (to avoid interrupting selection)
    var isUserInteracting by remember { mutableStateOf(false) }

    // Coroutine scope for delayed sync
    val scope = rememberCoroutineScope()
    var syncDelayJob by remember { mutableStateOf<Job?>(null) }

    // Sync when text or cursor/selection changes from viewModel
    // BUT: Don't interrupt the user while they're actively selecting text
    LaunchedEffect(text, cursorPosition, selection) {
        // Skip sync if user is actively interacting (selecting text)
        if (isUserInteracting) {
            return@LaunchedEffect
        }

        // Build the expected selection from ViewModel state
        val currentSelection = selection // Copy to local variable for smart cast
        val expectedSelection = if (currentSelection != null) {
            // There's an active selection
            TextRange(currentSelection.first.toInt(), currentSelection.second.toInt())
        } else {
            // Just a cursor position
            TextRange(cursorPosition.toInt())
        }

        val expectedTextFieldValue = TextFieldValue(
            text = text,
            selection = expectedSelection
        )

        // Only update if there's actually a difference to avoid infinite loops
        if (textFieldValue.text != expectedTextFieldValue.text ||
            textFieldValue.selection != expectedTextFieldValue.selection) {
            textFieldValue = expectedTextFieldValue
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Edit Note") },
                navigationIcon = {
                    IconButton(onClick = {
                        viewModel.saveContent()
                        onBack()
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { viewModel.undo() },
                        enabled = canUndo
                    ) {
                        Icon(Icons.AutoMirrored.Filled.Undo, "Undo")
                    }
                    IconButton(
                        onClick = { viewModel.redo() },
                        enabled = canRedo
                    ) {
                        Icon(Icons.AutoMirrored.Filled.Redo, "Redo")
                    }
                }
            )
        },
        contentWindowInsets = WindowInsets(0, 0, 0, 0)  // Don't consume insets, let content handle them
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Toolbar with formatting buttons
            FormattingToolbar(
                onOperation = { operation ->
                    // Cancel any pending sync delay
                    syncDelayJob?.cancel()

                    // Apply the operation
                    viewModel.applyOperation(operation)

                    // Clear interaction flag immediately to allow sync
                    // This ensures selection is cleared after the operation
                    isUserInteracting = false
                }
            )

            HorizontalDivider()

            // Editor with hybrid rendering
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .imePadding()  // Add padding when keyboard appears
                    .verticalScroll(rememberScrollState())  // Make the parent scrollable
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(16.dp)
            ) {
                HybridMarkdownEditor(
                    value = textFieldValue,
                    spans = spans,
                    onBoldClick = {
                        syncDelayJob?.cancel()
                        viewModel.applyOperation(MarkdownOperation.BOLD)
                        isUserInteracting = false
                    },
                    onItalicClick = {
                        syncDelayJob?.cancel()
                        viewModel.applyOperation(MarkdownOperation.ITALIC)
                        isUserInteracting = false
                    },
                    onStrikethroughClick = {
                        syncDelayJob?.cancel()
                        viewModel.applyOperation(MarkdownOperation.STRIKETHROUGH)
                        isUserInteracting = false
                    },
                    onValueChange = { newValue ->
                        // Mark that user is actively interacting
                        isUserInteracting = true

                        // Cancel any pending sync delay
                        syncDelayJob?.cancel()

                        // Check if a single newline character was just inserted
                        val oldText = textFieldValue.text
                        val newText = newValue.text
                        val oldCursor = textFieldValue.selection.end
                        val newCursor = newValue.selection.end

                        if (newText.length == oldText.length + 1 &&
                            newCursor == oldCursor + 1 &&
                            newCursor > 0 &&
                            newText[newCursor - 1] == '\n'
                        ) {
                            // User just typed a newline - use smart newline insertion
                            textFieldValue = newValue
                            viewModel.insertNewline()

                            // Reset interaction flag immediately after operation
                            isUserInteracting = false
                        } else {
                            textFieldValue = newValue
                            viewModel.updateText(
                                newText = newValue.text,
                                cursorPos = newValue.selection.end,
                                selectionStart = newValue.selection.start,
                                selectionEnd = newValue.selection.end
                            )

                            // Schedule delayed reset of interaction flag
                            // This allows the user to finish their selection gesture
                            syncDelayJob = scope.launch {
                                delay(150) // Wait 150ms after last input before allowing sync
                                isUserInteracting = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxSize()
                )
            }
        }
    }
}

/**
 * Toolbar with markdown formatting buttons
 */
@Composable
fun FormattingToolbar(onOperation: (MarkdownOperation) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 8.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.BOLD) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("B", fontWeight = FontWeight.Bold)
        }
        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.ITALIC) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("I", fontStyle = FontStyle.Italic)
        }
        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.STRIKETHROUGH) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("S", textDecoration = TextDecoration.LineThrough)
        }

        VerticalDivider(modifier = Modifier.height(32.dp).padding(vertical = 4.dp))

        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.HEADER1) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("H1", fontSize = 12.sp)
        }
        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.HEADER2) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("H2", fontSize = 12.sp)
        }
        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.HEADER3) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("H3", fontSize = 12.sp)
        }

        VerticalDivider(modifier = Modifier.height(32.dp).padding(vertical = 4.dp))

        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.BLOCKQUOTE) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("❝", fontSize = 16.sp)
        }

        VerticalDivider(modifier = Modifier.height(32.dp).padding(vertical = 4.dp))

        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.CREATE_UNORDERED_LIST) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("• List", fontSize = 12.sp)
        }
        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.CREATE_ORDERED_LIST) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("1. List", fontSize = 12.sp)
        }

        VerticalDivider(modifier = Modifier.height(32.dp).padding(vertical = 4.dp))

        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.INDENT_LIST) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("→", fontSize = 16.sp)
        }
        FilledTonalButton(
            onClick = { onOperation(MarkdownOperation.UNINDENT_LIST) },
            modifier = Modifier.height(40.dp)
        ) {
            Text("←", fontSize = 16.sp)
        }
    }
}

/**
 * Hybrid markdown editor with styled text overlay
 * Similar to the web version - shows markdown syntax with live styling
 */
@Composable
fun HybridMarkdownEditor(
    value: TextFieldValue,
    spans: List<MarkdownStyledSpan>,
    onValueChange: (TextFieldValue) -> Unit,
    onBoldClick: () -> Unit,
    onItalicClick: () -> Unit,
    onStrikethroughClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    // Build annotated string with styles
    val styledText = remember(value.text, spans) {
        buildStyledText(value.text, spans)
    }

    val selectionColors = TextSelectionColors(
        handleColor = MaterialTheme.colorScheme.primary,
        backgroundColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.4f) // Semi-transparent selection
    )

    // Create custom text toolbar that adds our formatting actions
    val defaultTextToolbar = LocalTextToolbar.current
    val customTextToolbar = remember(onBoldClick, onItalicClick, onStrikethroughClick) {
        CustomTextToolbar(
            defaultToolbar = defaultTextToolbar,
            onBoldClick = onBoldClick,
            onItalicClick = onItalicClick,
            onStrikethroughClick = onStrikethroughClick
        )
    }

    Box {
        CompositionLocalProvider(
            LocalTextSelectionColors provides selectionColors,
            LocalTextToolbar provides customTextToolbar
        ) {
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                modifier = modifier,
                textStyle = MaterialTheme.typography.bodyLarge.copy(
                    color = Color.Transparent,  // Make text transparent so only styled overlay is visible
                    lineHeight = 24.sp,
                    fontFamily = FontFamily.Monospace  // Use monospace to ensure cursor aligns with styled text
                ),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                decorationBox = { innerTextField ->
                    Box {
                        // Styled overlay showing markdown with formatting
                        Text(
                            text = styledText,
                            style = MaterialTheme.typography.bodyLarge.copy(
                                lineHeight = 24.sp,
                                fontFamily = FontFamily.Monospace  // Must match textStyle for cursor alignment
                            )
                        )
                        // Invisible text field for input (text is transparent, cursor/selection visible)
                        innerTextField()
                    }
                }
            )
        }

        // Render the custom toolbar's content
        customTextToolbar.Content()
    }
}

/**
 * Build annotated string with markdown styles applied
 * Note: Rust library now returns UTF-16 offsets which match Kotlin's Char indices
 */
private fun buildStyledText(text: String, spans: List<MarkdownStyledSpan>): AnnotatedString {
    return buildAnnotatedString {
        append(text)

        // Apply styles from spans (offsets are already UTF-16 from Rust)
        spans.forEach { span ->
            val start = span.start.toInt()
            val end = span.end.toInt()

            if (start < text.length && end <= text.length && start < end) {
                val style = when (span.style) {
                    MarkdownSpanStyle.BOLD -> SpanStyle(fontWeight = FontWeight.Bold)
                    MarkdownSpanStyle.ITALIC -> SpanStyle(fontStyle = FontStyle.Italic)
                    MarkdownSpanStyle.STRIKETHROUGH -> SpanStyle(textDecoration = TextDecoration.LineThrough)
                    MarkdownSpanStyle.HEADER1, MarkdownSpanStyle.HEADER2, MarkdownSpanStyle.HEADER3,
                    MarkdownSpanStyle.HEADER4, MarkdownSpanStyle.HEADER5, MarkdownSpanStyle.HEADER6 ->
                        SpanStyle(color = Color(0xFF8B6DFF), fontWeight = FontWeight.Bold)
                    MarkdownSpanStyle.CODE -> SpanStyle(background = Color(0x4D9B59B6))
                    MarkdownSpanStyle.LINK -> SpanStyle(color = Color(0xFF5DADE2), textDecoration = TextDecoration.Underline)
                    MarkdownSpanStyle.BLOCKQUOTE -> SpanStyle(color = Color(0xFFA991D4), fontStyle = FontStyle.Italic)
                    MarkdownSpanStyle.MARKDOWN_MARKER -> SpanStyle(color = Color.Gray.copy(alpha = 0.7f))
                    else -> null
                }

                style?.let { addStyle(it, start, end) }
            }
        }
    }
}

/**
 * Custom text toolbar that integrates formatting actions with standard text actions.
 * Shows Copy, Paste, Cut, Select All + Bold, Italic, Strikethrough in a unified menu.
 */
class CustomTextToolbar(
    private val defaultToolbar: TextToolbar,
    private val onBoldClick: () -> Unit,
    private val onItalicClick: () -> Unit,
    private val onStrikethroughClick: () -> Unit
) : TextToolbar {

    private var _status: TextToolbarStatus by mutableStateOf(TextToolbarStatus.Hidden)
    private var toolbarRect: Rect? by mutableStateOf(null)
    private var copyCallback: (() -> Unit)? by mutableStateOf(null)
    private var pasteCallback: (() -> Unit)? by mutableStateOf(null)
    private var cutCallback: (() -> Unit)? by mutableStateOf(null)
    private var selectAllCallback: (() -> Unit)? by mutableStateOf(null)

    override val status: TextToolbarStatus
        get() = _status

    @Composable
    fun Content() {
        if (_status == TextToolbarStatus.Shown && toolbarRect != null) {
            Popup(
                onDismissRequest = { hide() },
                properties = PopupProperties(focusable = false)
            ) {
                Surface(
                    modifier = Modifier
                        .wrapContentSize()
                        .padding(8.dp),
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    tonalElevation = 6.dp,
                    shadowElevation = 6.dp
                ) {
                    Row(
                        modifier = Modifier
                            .horizontalScroll(rememberScrollState())
                            .padding(4.dp),
                        horizontalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        // Standard clipboard actions
                        cutCallback?.let { callback ->
                            TextButton(
                                onClick = {
                                    callback()
                                    hide()
                                },
                                modifier = Modifier.height(36.dp),
                                contentPadding = PaddingValues(horizontal = 8.dp)
                            ) {
                                Text("Cut", fontSize = 13.sp)
                            }
                        }

                        copyCallback?.let { callback ->
                            TextButton(
                                onClick = {
                                    callback()
                                    hide()
                                },
                                modifier = Modifier.height(36.dp),
                                contentPadding = PaddingValues(horizontal = 8.dp)
                            ) {
                                Text("Copy", fontSize = 13.sp)
                            }
                        }

                        pasteCallback?.let { callback ->
                            TextButton(
                                onClick = {
                                    callback()
                                    hide()
                                },
                                modifier = Modifier.height(36.dp),
                                contentPadding = PaddingValues(horizontal = 8.dp)
                            ) {
                                Text("Paste", fontSize = 13.sp)
                            }
                        }

                        selectAllCallback?.let { callback ->
                            TextButton(
                                onClick = {
                                    callback()
                                    // Don't hide after select all - user may want to format
                                },
                                modifier = Modifier.height(36.dp),
                                contentPadding = PaddingValues(horizontal = 8.dp)
                            ) {
                                Text("Select All", fontSize = 13.sp)
                            }
                        }

                        // Divider before formatting actions
                        if (copyCallback != null || pasteCallback != null || cutCallback != null || selectAllCallback != null) {
                            VerticalDivider(
                                modifier = Modifier
                                    .height(32.dp)
                                    .padding(horizontal = 4.dp)
                            )
                        }

                        // Formatting actions
                        TextButton(
                            onClick = {
                                onBoldClick()
                                hide()
                            },
                            modifier = Modifier.height(36.dp),
                            contentPadding = PaddingValues(horizontal = 8.dp)
                        ) {
                            Text("B", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }

                        TextButton(
                            onClick = {
                                onItalicClick()
                                hide()
                            },
                            modifier = Modifier.height(36.dp),
                            contentPadding = PaddingValues(horizontal = 8.dp)
                        ) {
                            Text("I", fontStyle = FontStyle.Italic, fontSize = 13.sp)
                        }

                        TextButton(
                            onClick = {
                                onStrikethroughClick()
                                hide()
                            },
                            modifier = Modifier.height(36.dp),
                            contentPadding = PaddingValues(horizontal = 8.dp)
                        ) {
                            Text(
                                "S",
                                fontSize = 13.sp,
                                style = MaterialTheme.typography.bodyMedium.copy(
                                    textDecoration = TextDecoration.LineThrough
                                )
                            )
                        }
                    }
                }
            }
        }
    }

    override fun showMenu(
        rect: Rect,
        onCopyRequested: (() -> Unit)?,
        onPasteRequested: (() -> Unit)?,
        onCutRequested: (() -> Unit)?,
        onSelectAllRequested: (() -> Unit)?
    ) {
        toolbarRect = rect
        copyCallback = onCopyRequested
        pasteCallback = onPasteRequested
        cutCallback = onCutRequested
        selectAllCallback = onSelectAllRequested
        _status = TextToolbarStatus.Shown
    }

    override fun hide() {
        _status = TextToolbarStatus.Hidden
        toolbarRect = null
        copyCallback = null
        pasteCallback = null
        cutCallback = null
        selectAllCallback = null
    }
}
