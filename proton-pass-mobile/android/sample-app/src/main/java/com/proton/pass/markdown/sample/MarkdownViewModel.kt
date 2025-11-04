package com.proton.pass.markdown.sample

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import proton.android.pass.commonrust.MarkdownEditor
import proton.android.pass.commonrust.MarkdownOperation
import proton.android.pass.commonrust.MarkdownStyledSpan

/**
 * ViewModel for managing markdown editor state and operations.
 *
 * This class demonstrates how to integrate the Rust-based markdown editor
 * into an Android app using Jetpack Compose and MVVM architecture.
 */
class MarkdownViewModel(application: Application) : AndroidViewModel(application) {

    private val storage = MarkdownStorage(application)

    // Markdown editor instance from Rust library
    private var editor: MarkdownEditor? = null

    // Current text content
    private val _text = MutableStateFlow("")
    val text: StateFlow<String> = _text.asStateFlow()

    // Styled spans for rendering
    private val _styledSpans = MutableStateFlow<List<MarkdownStyledSpan>>(emptyList())
    val styledSpans: StateFlow<List<MarkdownStyledSpan>> = _styledSpans.asStateFlow()

    // Cursor position in bytes (UTF-8)
    private val _cursorPosition = MutableStateFlow(0u)
    val cursorPosition: StateFlow<UInt> = _cursorPosition.asStateFlow()

    // Selection range (start, end) in bytes, null if no selection
    private val _selection = MutableStateFlow<Pair<UInt, UInt>?>(null)
    val selection: StateFlow<Pair<UInt, UInt>?> = _selection.asStateFlow()

    // Undo/Redo availability
    var canUndo by mutableStateOf(false)
        private set
    var canRedo by mutableStateOf(false)
        private set

    // Loading state
    private val _isLoading = MutableStateFlow(true)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    // Undo batching - saves state after delay when typing stops
    private var undoBatchJob: Job? = null
    private val UNDO_BATCH_DELAY_MS = 1000L

    init {
        loadContent()
    }

    /**
     * Load content from persistent storage
     */
    private fun loadContent() {
        viewModelScope.launch {
            storage.contentFlow.collect { content ->
                initializeEditor(content)
                _isLoading.value = false
            }
        }
    }

    /**
     * Initialize the markdown editor with content
     */
    private fun initializeEditor(content: String) {
        editor = MarkdownEditor(content)
        _text.value = content
        updateRendering()
        updateUndoRedoState()
    }

    /**
     * Update text content (called when user types)
     * This syncs with the native text input without saving undo state on every keystroke
     */
    fun updateText(newText: String, cursorPos: Int, selectionStart: Int? = null, selectionEnd: Int? = null) {
        editor?.let { ed ->
            // Rust API now expects UTF-16 offsets directly (no conversion needed!)
            // TextField gives us UTF-16 positions, Rust accepts UTF-16 positions
            val cursorUtf16 = cursorPos.toUInt()

            // Update editor (set_text doesn't save undo state)
            ed.setText(newText)
            ed.setCursor(cursorUtf16)

            if (selectionStart != null && selectionEnd != null && selectionStart != selectionEnd) {
                val startUtf16 = selectionStart.toUInt()
                val endUtf16 = selectionEnd.toUInt()
                ed.setSelection(startUtf16, endUtf16)
                // Read back the selection in case it was adjusted
                val actualSelection = ed.getSelection()
                _selection.value = actualSelection?.let { Pair(it.start, it.end) }
            } else {
                _selection.value = null
            }

            _text.value = newText
            // Read back the actual cursor position in case it was adjusted to a valid boundary
            _cursorPosition.value = ed.getCursor()
            updateRendering()

            // Smart undo batching: save immediately on word boundary, otherwise after delay
            val lastChar = newText.lastOrNull()
            if (lastChar == ' ' || lastChar == '\n' || lastChar == '\t') {
                // Word boundary - save immediately
                undoBatchJob?.cancel()
                ed.saveUndoState()
                updateUndoRedoState()
            } else {
                // Schedule save after typing stops
                scheduleUndoSave()
            }
        }
    }

    /**
     * Schedule an undo state save after a delay (batching keystrokes)
     */
    private fun scheduleUndoSave() {
        undoBatchJob?.cancel()
        undoBatchJob = viewModelScope.launch {
            delay(UNDO_BATCH_DELAY_MS)
            editor?.saveUndoState()
            updateUndoRedoState()
        }
    }

    /**
     * Apply a markdown operation (bold, italic, etc.)
     */
    fun applyOperation(operation: MarkdownOperation) {
        editor?.let { ed ->
            try {
                ed.applyOperation(operation)
                _text.value = ed.getText()
                _cursorPosition.value = ed.getCursor()

                // Read back selection state - operations typically clear selection
                val actualSelection = ed.getSelection()
                _selection.value = actualSelection?.let { Pair(it.start, it.end) }

                updateRendering()
                updateUndoRedoState()
            } catch (e: Exception) {
                // Handle errors (invalid selection, etc.)
                e.printStackTrace()
            }
        }
    }

    /**
     * Insert a newline with smart list continuation
     */
    fun insertNewline() {
        editor?.let { ed ->
            try {
                ed.insertNewline()
                _text.value = ed.getText()
                _cursorPosition.value = ed.getCursor()

                // Read back selection state
                val actualSelection = ed.getSelection()
                _selection.value = actualSelection?.let { Pair(it.start, it.end) }

                updateRendering()
                updateUndoRedoState()
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    /**
     * Undo the last operation
     */
    fun undo() {
        editor?.let { ed ->
            if (ed.undo()) {
                _text.value = ed.getText()
                _cursorPosition.value = ed.getCursor()

                // Read back selection state
                val actualSelection = ed.getSelection()
                _selection.value = actualSelection?.let { Pair(it.start, it.end) }

                updateRendering()
                updateUndoRedoState()
            }
        }
    }

    /**
     * Redo the last undone operation
     */
    fun redo() {
        editor?.let { ed ->
            if (ed.redo()) {
                _text.value = ed.getText()
                _cursorPosition.value = ed.getCursor()

                // Read back selection state
                val actualSelection = ed.getSelection()
                _selection.value = actualSelection?.let { Pair(it.start, it.end) }

                updateRendering()
                updateUndoRedoState()
            }
        }
    }

    /**
     * Update the styled spans for rendering
     */
    private fun updateRendering() {
        editor?.let { ed ->
            _styledSpans.value = ed.render()
        }
    }

    /**
     * Update undo/redo availability state
     */
    private fun updateUndoRedoState() {
        editor?.let { ed ->
            canUndo = ed.canUndo()
            canRedo = ed.canRedo()
        }
    }

    /**
     * Save current content to persistent storage
     */
    fun saveContent() {
        viewModelScope.launch {
            _text.value.let { content ->
                storage.saveContent(content)
            }
        }
    }

    /**
     * Get current text (for external access)
     */
    fun getCurrentText(): String = _text.value

    override fun onCleared() {
        super.onCleared()
        undoBatchJob?.cancel()
    }
}
