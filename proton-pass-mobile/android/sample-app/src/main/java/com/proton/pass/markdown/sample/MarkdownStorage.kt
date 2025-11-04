package com.proton.pass.markdown.sample

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * Handles persistent storage of markdown content using DataStore.
 * This is a simple implementation for demo purposes - in production you might use
 * Room database or encrypted storage depending on your needs.
 */
class MarkdownStorage(private val context: Context) {

    companion object {
        private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "markdown_storage")
        private val MARKDOWN_CONTENT_KEY = stringPreferencesKey("markdown_content")

        private const val DEFAULT_CONTENT = """# Welcome to Proton Pass Markdown Editor!

Start editing to see the **live preview** with styled text.

## Features

- **Bold** text with double asterisks
- *Italic* text with single asterisks
- ~~Strikethrough~~ text with tildes
- Headers from H1 to H6
- > Blockquotes with angle brackets
- Ordered and unordered lists
- Full undo/redo support

## Try it!

Select some text and tap the formatting buttons, or type markdown syntax directly. The text will be styled in real-time as you type!

> This is a blockquote. Markdown markers are visible but text is styled for better readability."""
    }

    /**
     * Flow of the current markdown content
     */
    val contentFlow: Flow<String> = context.dataStore.data.map { preferences ->
        preferences[MARKDOWN_CONTENT_KEY] ?: DEFAULT_CONTENT
    }

    /**
     * Save markdown content to persistent storage
     */
    suspend fun saveContent(content: String) {
        context.dataStore.edit { preferences ->
            preferences[MARKDOWN_CONTENT_KEY] = content
        }
    }

    /**
     * Clear saved content and reset to default
     */
    suspend fun clearContent() {
        context.dataStore.edit { preferences ->
            preferences.remove(MARKDOWN_CONTENT_KEY)
        }
    }
}
