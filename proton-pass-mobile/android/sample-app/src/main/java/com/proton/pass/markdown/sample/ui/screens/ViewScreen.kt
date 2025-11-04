package com.proton.pass.markdown.sample.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.proton.pass.markdown.sample.MarkdownViewModel
import proton.android.pass.commonrust.MarkdownSpanStyle
import proton.android.pass.commonrust.MarkdownStyledSpan

/**
 * View screen showing rendered markdown content
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ViewScreen(
    viewModel: MarkdownViewModel,
    onEdit: () -> Unit
) {
    val text by viewModel.text.collectAsStateWithLifecycle()
    val spans by viewModel.styledSpans.collectAsStateWithLifecycle()
    val isLoading by viewModel.isLoading.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("My Markdown Note") },
                actions = {
                    IconButton(onClick = onEdit) {
                        Icon(Icons.Default.Edit, contentDescription = "Edit")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onEdit,
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(Icons.Default.Edit, contentDescription = "Edit")
            }
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            when {
                isLoading -> {
                    CircularProgressIndicator(
                        modifier = Modifier.align(Alignment.Center)
                    )
                }
                text.isBlank() -> {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "📝",
                            fontSize = 64.sp,
                            modifier = Modifier.padding(bottom = 16.dp)
                        )
                        Text(
                            text = "No note saved yet",
                            style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.padding(bottom = 8.dp)
                        )
                        Text(
                            text = "Tap the edit button to create one!",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                else -> {
                    RenderedMarkdown(
                        text = text,
                        spans = spans,
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(16.dp)
                    )
                }
            }
        }
    }
}

/**
 * Rendered markdown content with full styling
 * (hides markdown syntax markers)
 */
@Composable
fun RenderedMarkdown(
    text: String,
    spans: List<MarkdownStyledSpan>,
    modifier: Modifier = Modifier
) {
    val renderedText = buildAnnotatedString {
        // Separate marker and content spans
        val markerSpans = spans.filter { it.style == MarkdownSpanStyle.MARKDOWN_MARKER }
            .sortedBy { it.start.toInt() }
        val contentSpans = spans.filter { it.style != MarkdownSpanStyle.MARKDOWN_MARKER }
        val listItemSpans = spans.filter {
            it.style == MarkdownSpanStyle.ORDERED_LIST_ITEM ||
            it.style == MarkdownSpanStyle.UNORDERED_LIST_ITEM
        }

        // Build text without markers and track offset adjustments
        val cleanedText = StringBuilder()
        var currentPos = 0
        val offsetMap = mutableMapOf<Int, Int>() // original offset -> cleaned offset

        // Track how much we've removed/added up to each position
        var totalAdjustment = 0

        // Process text line by line to handle list items
        val lines = text.lines()
        var lineStartOffset = 0

        for ((lineIndex, line) in lines.withIndex()) {
            // Check if this line is a list item
            val lineListItem = listItemSpans.find { span ->
                val spanStart = span.start.toInt()
                spanStart >= lineStartOffset && spanStart < lineStartOffset + line.length
            }

            // Find markers on this line
            val lineMarkers = markerSpans.filter { marker ->
                val markerStart = marker.start.toInt()
                markerStart >= lineStartOffset && markerStart < lineStartOffset + line.length
            }

            if (lineListItem != null) {
                // This is a list item - replace markdown marker with visual indicator
                val isOrdered = lineListItem.style == MarkdownSpanStyle.ORDERED_LIST_ITEM
                val listMarker = if (isOrdered) {
                    "${lineListItem.number ?: 1}. "
                } else {
                    "• "
                }

                // Map the start of the line
                offsetMap[lineStartOffset] = cleanedText.length

                // Add the visual list marker
                cleanedText.append(listMarker)
                totalAdjustment += listMarker.length

                // Add the line content, skipping markdown markers
                var linePos = lineStartOffset
                for (marker in lineMarkers) {
                    val markerStart = marker.start.toInt()
                    val markerEnd = marker.end.toInt()

                    // Add text before marker
                    if (linePos < markerStart) {
                        cleanedText.append(text.substring(linePos, markerStart))
                        for (i in linePos until markerStart) {
                            offsetMap[i] = cleanedText.length - (markerStart - i)
                        }
                    }

                    // Skip marker
                    totalAdjustment -= (markerEnd - markerStart)
                    linePos = markerEnd
                    offsetMap[markerEnd] = cleanedText.length
                }

                // Add remaining line content
                if (linePos < lineStartOffset + line.length) {
                    cleanedText.append(text.substring(linePos, lineStartOffset + line.length))
                    for (i in linePos until lineStartOffset + line.length) {
                        offsetMap[i] = cleanedText.length - (lineStartOffset + line.length - i)
                    }
                }
            } else {
                // Not a list item - process normally
                var linePos = lineStartOffset
                for (marker in lineMarkers) {
                    val markerStart = marker.start.toInt()
                    val markerEnd = marker.end.toInt()

                    // Add text before marker
                    if (linePos < markerStart) {
                        cleanedText.append(text.substring(linePos, markerStart))
                        for (i in linePos until markerStart) {
                            offsetMap[i] = cleanedText.length - (markerStart - i)
                        }
                    }

                    // Skip marker
                    totalAdjustment -= (markerEnd - markerStart)
                    linePos = markerEnd
                    offsetMap[markerEnd] = cleanedText.length
                }

                // Add remaining line content
                if (linePos < lineStartOffset + line.length) {
                    cleanedText.append(text.substring(linePos, lineStartOffset + line.length))
                    for (i in linePos until lineStartOffset + line.length) {
                        offsetMap[i] = cleanedText.length - (lineStartOffset + line.length - i)
                    }
                }
            }

            // Add newline if not the last line
            if (lineIndex < lines.size - 1) {
                cleanedText.append('\n')
                offsetMap[lineStartOffset + line.length] = cleanedText.length - 1
            }

            lineStartOffset += line.length + 1 // +1 for the newline
        }

        // Map the end position
        offsetMap[text.length] = cleanedText.length

        append(cleanedText.toString())

        // Apply styles with adjusted offsets
        contentSpans.forEach { span ->
            val originalStart = span.start.toInt()
            val originalEnd = span.end.toInt()

            // Find the closest mapped offsets
            val adjustedStart = offsetMap[originalStart] ?: offsetMap.entries
                .filter { it.key <= originalStart }
                .maxByOrNull { it.key }?.value ?: 0

            val adjustedEnd = offsetMap[originalEnd] ?: offsetMap.entries
                .filter { it.key <= originalEnd }
                .maxByOrNull { it.key }?.value ?: cleanedText.length

            if (adjustedStart < cleanedText.length && adjustedEnd <= cleanedText.length && adjustedStart < adjustedEnd) {
                when (span.style) {
                    MarkdownSpanStyle.BOLD -> {
                        addStyle(SpanStyle(fontWeight = FontWeight.Bold), adjustedStart, adjustedEnd)
                    }
                    MarkdownSpanStyle.ITALIC -> {
                        addStyle(SpanStyle(fontStyle = FontStyle.Italic), adjustedStart, adjustedEnd)
                    }
                    MarkdownSpanStyle.STRIKETHROUGH -> {
                        addStyle(SpanStyle(textDecoration = TextDecoration.LineThrough), adjustedStart, adjustedEnd)
                    }
                    MarkdownSpanStyle.HEADER1 -> {
                        addStyle(
                            SpanStyle(
                                fontSize = 32.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF6D4AFF)
                            ),
                            adjustedStart,
                            adjustedEnd
                        )
                    }
                    MarkdownSpanStyle.HEADER2 -> {
                        addStyle(
                            SpanStyle(
                                fontSize = 24.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF6D4AFF)
                            ),
                            adjustedStart,
                            adjustedEnd
                        )
                    }
                    MarkdownSpanStyle.HEADER3 -> {
                        addStyle(
                            SpanStyle(
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF6D4AFF)
                            ),
                            adjustedStart,
                            adjustedEnd
                        )
                    }
                    MarkdownSpanStyle.CODE -> {
                        addStyle(
                            SpanStyle(
                                background = Color(0x1A9B59B6),
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                            ),
                            adjustedStart,
                            adjustedEnd
                        )
                    }
                    MarkdownSpanStyle.LINK -> {
                        addStyle(
                            SpanStyle(
                                color = Color(0xFF5DADE2),
                                textDecoration = TextDecoration.Underline
                            ),
                            adjustedStart,
                            adjustedEnd
                        )
                    }
                    MarkdownSpanStyle.BLOCKQUOTE -> {
                        addStyle(
                            SpanStyle(
                                color = Color(0xFF9575CD),
                                fontStyle = FontStyle.Italic
                            ),
                            adjustedStart,
                            adjustedEnd
                        )
                    }
                    MarkdownSpanStyle.ORDERED_LIST_ITEM, MarkdownSpanStyle.UNORDERED_LIST_ITEM -> {
                        addStyle(SpanStyle(color = Color(0xFF43A047)), adjustedStart, adjustedEnd)
                    }
                    else -> {}
                }
            }
        }
    }

    Text(
        text = renderedText,
        style = MaterialTheme.typography.bodyLarge.copy(lineHeight = 28.sp),
        modifier = modifier
    )
}
