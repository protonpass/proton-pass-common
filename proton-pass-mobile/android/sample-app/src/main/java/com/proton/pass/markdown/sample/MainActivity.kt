package com.proton.pass.markdown.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import com.proton.pass.markdown.sample.ui.theme.MarkdownSampleTheme

/**
 * Main Activity for the Proton Pass Markdown Sample App
 *
 * This sample demonstrates how to integrate the Rust-based markdown library
 * into an Android application using:
 * - Jetpack Compose for modern UI
 * - MVVM architecture with ViewModel
 * - UniFFI for Rust-Kotlin interop
 * - DataStore for persistence
 * - Navigation Compose for screen navigation
 *
 * Features:
 * - View screen: Displays rendered markdown with full styling
 * - Edit screen: Hybrid markdown editor with live syntax highlighting
 * - Smart undo/redo with batching
 * - Persistent storage
 * - Formatting toolbar (Bold, Italic, Strikethrough, Headers, Lists, Blockquotes)
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            MarkdownSampleTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val viewModel: MarkdownViewModel = viewModel()
                    AppNavigation(viewModel = viewModel)
                }
            }
        }
    }
}
