use super::utf16;
use pulldown_cmark::{Event, Parser, Tag, TagEnd};

/// Represents a styled span in the rendered markdown
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StyledSpan {
    /// Start position in the text (UTF-16 code unit offset for client compatibility)
    pub start: u32,
    /// End position in the text (UTF-16 code unit offset for client compatibility)
    pub end: u32,
    /// The style to apply
    pub style: SpanStyle,
}

/// Different styles that can be applied to text spans
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanStyle {
    Bold,
    Italic,
    Strikethrough,
    Header(u8), // 1-6
    Code,
    CodeBlock,
    Link {
        url: String,
    },
    OrderedListItem {
        level: u8,
        number: u32,
    },
    UnorderedListItem {
        level: u8,
    },
    Blockquote,
    /// Markdown syntax markers (**, *, ~~, #, -, `, etc.) - styled differently for hybrid mode
    MarkdownMarker,
}

/// Render markdown text into styled spans (hybrid mode: shows markers + applies styles)
pub fn render_markdown(text: &str) -> Vec<StyledSpan> {
    let mut spans = Vec::new();
    let mut options = pulldown_cmark::Options::empty();
    options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(text, options);

    let mut stack: Vec<(SpanStyle, usize)> = Vec::new();
    let mut current_list_level: Vec<ListInfo> = Vec::new();

    for (event, range) in parser.into_offset_iter() {
        match event {
            Event::Start(tag) => {
                let style = match tag {
                    Tag::Strong => Some(SpanStyle::Bold),
                    Tag::Emphasis => Some(SpanStyle::Italic),
                    Tag::Strikethrough => Some(SpanStyle::Strikethrough),
                    Tag::Heading { level, .. } => Some(SpanStyle::Header(level as u8)),
                    Tag::Link { dest_url, .. } => Some(SpanStyle::Link {
                        url: dest_url.to_string(),
                    }),
                    Tag::CodeBlock(_) => Some(SpanStyle::CodeBlock),
                    Tag::BlockQuote(_) => Some(SpanStyle::Blockquote),
                    Tag::List(start_number) => {
                        let _level = current_list_level.len() as u8;
                        current_list_level.push(ListInfo {
                            is_ordered: start_number.is_some(),
                            current_number: start_number.unwrap_or(1) as u32,
                        });
                        None
                    }
                    Tag::Item => {
                        let level = (current_list_level.len() - 1) as u8;
                        if let Some(list_info) = current_list_level.last() {
                            let style = if list_info.is_ordered {
                                SpanStyle::OrderedListItem {
                                    level,
                                    number: list_info.current_number,
                                }
                            } else {
                                SpanStyle::UnorderedListItem { level }
                            };
                            // Increment counter for next item
                            if let Some(list_info_mut) = current_list_level.last_mut() {
                                list_info_mut.current_number += 1;
                            }
                            Some(style)
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                if let Some(style) = style {
                    stack.push((style, range.start));
                }
            }
            Event::End(tag_end) => {
                let should_pop = match tag_end {
                    TagEnd::Strong
                    | TagEnd::Emphasis
                    | TagEnd::Strikethrough
                    | TagEnd::Heading(_)
                    | TagEnd::Link
                    | TagEnd::CodeBlock
                    | TagEnd::BlockQuote(_)
                    | TagEnd::Item => true,
                    TagEnd::List(_) => {
                        current_list_level.pop();
                        false
                    }
                    _ => false,
                };

                if should_pop {
                    if let Some((style, start)) = stack.pop() {
                        // Only create span if there's actual content
                        if range.end > start {
                            // Add marker spans for hybrid mode
                            add_marker_spans(text, start, range.end, &style, &mut spans);

                            // Add the content span with styling
                            spans.push(StyledSpan {
                                start: start as u32,
                                end: range.end as u32,
                                style,
                            });
                        }
                    }
                }
            }
            Event::Code(_) => {
                // Inline code - add marker and content spans
                if range.end > range.start {
                    // Add marker for backticks
                    add_marker_spans(text, range.start, range.end, &SpanStyle::Code, &mut spans);

                    spans.push(StyledSpan {
                        start: range.start as u32,
                        end: range.end as u32,
                        style: SpanStyle::Code,
                    });
                }
            }
            _ => {}
        }
    }

    // Convert all UTF-8 byte offsets to UTF-16 code unit offsets for client compatibility
    convert_spans_to_utf16(text, spans)
}

/// Convert all spans from UTF-8 byte offsets to UTF-16 code unit offsets
fn convert_spans_to_utf16(text: &str, spans: Vec<StyledSpan>) -> Vec<StyledSpan> {
    spans
        .into_iter()
        .map(|span| StyledSpan {
            start: utf16::utf8_to_utf16_offset(text, span.start as usize) as u32,
            end: utf16::utf8_to_utf16_offset(text, span.end as usize) as u32,
            style: span.style,
        })
        .collect()
}

/// Add marker spans for a styled region (hybrid mode)
fn add_marker_spans(text: &str, start: usize, end: usize, style: &SpanStyle, spans: &mut Vec<StyledSpan>) {
    if start >= end || end > text.len() {
        return;
    }

    let region = &text[start..end];

    match style {
        SpanStyle::Bold => {
            // Check for ** or __
            if region.starts_with("**") && region.ends_with("**") && region.len() >= 4 {
                // Opening **
                spans.push(StyledSpan {
                    start: start as u32,
                    end: (start + 2) as u32,
                    style: SpanStyle::MarkdownMarker,
                });
                // Closing **
                spans.push(StyledSpan {
                    start: (end - 2) as u32,
                    end: end as u32,
                    style: SpanStyle::MarkdownMarker,
                });
            } else if region.starts_with("__") && region.ends_with("__") && region.len() >= 4 {
                // Opening __
                spans.push(StyledSpan {
                    start: start as u32,
                    end: (start + 2) as u32,
                    style: SpanStyle::MarkdownMarker,
                });
                // Closing __
                spans.push(StyledSpan {
                    start: (end - 2) as u32,
                    end: end as u32,
                    style: SpanStyle::MarkdownMarker,
                });
            }
        }
        SpanStyle::Italic => {
            // Check for * or _
            if region.starts_with('*') && region.ends_with('*') && region.len() >= 2 {
                // Opening *
                spans.push(StyledSpan {
                    start: start as u32,
                    end: (start + 1) as u32,
                    style: SpanStyle::MarkdownMarker,
                });
                // Closing *
                spans.push(StyledSpan {
                    start: (end - 1) as u32,
                    end: end as u32,
                    style: SpanStyle::MarkdownMarker,
                });
            } else if region.starts_with('_') && region.ends_with('_') && region.len() >= 2 {
                // Opening _
                spans.push(StyledSpan {
                    start: start as u32,
                    end: (start + 1) as u32,
                    style: SpanStyle::MarkdownMarker,
                });
                // Closing _
                spans.push(StyledSpan {
                    start: (end - 1) as u32,
                    end: end as u32,
                    style: SpanStyle::MarkdownMarker,
                });
            }
        }
        SpanStyle::Strikethrough => {
            // Check for ~~
            if region.starts_with("~~") && region.ends_with("~~") && region.len() >= 4 {
                // Opening ~~
                spans.push(StyledSpan {
                    start: start as u32,
                    end: (start + 2) as u32,
                    style: SpanStyle::MarkdownMarker,
                });
                // Closing ~~
                spans.push(StyledSpan {
                    start: (end - 2) as u32,
                    end: end as u32,
                    style: SpanStyle::MarkdownMarker,
                });
            }
        }
        SpanStyle::Header(level) => {
            // Headers start with # (1-6 times)
            let level = *level as usize;
            let prefix = "#".repeat(level);
            if region.starts_with(&prefix) {
                // Mark the # symbols and following space if present
                let mut marker_end = start + level;
                if text[marker_end..].starts_with(' ') {
                    marker_end += 1;
                }
                spans.push(StyledSpan {
                    start: start as u32,
                    end: marker_end as u32,
                    style: SpanStyle::MarkdownMarker,
                });
            }
        }
        SpanStyle::Code => {
            // Inline code with backticks
            if region.starts_with('`') && region.ends_with('`') && region.len() >= 2 {
                // Opening `
                spans.push(StyledSpan {
                    start: start as u32,
                    end: (start + 1) as u32,
                    style: SpanStyle::MarkdownMarker,
                });
                // Closing `
                spans.push(StyledSpan {
                    start: (end - 1) as u32,
                    end: end as u32,
                    style: SpanStyle::MarkdownMarker,
                });
            }
        }
        SpanStyle::CodeBlock => {
            // Code blocks with ```
            if region.starts_with("```") {
                // Find the end of the first line (opening fence + language identifier)
                if let Some(newline_pos) = region.find('\n') {
                    spans.push(StyledSpan {
                        start: start as u32,
                        end: (start + newline_pos + 1) as u32,
                        style: SpanStyle::MarkdownMarker,
                    });
                }
            }
            if region.ends_with("```") {
                // Find the start of the last line (closing fence)
                if let Some(newline_pos) = region.rfind('\n') {
                    spans.push(StyledSpan {
                        start: (start + newline_pos) as u32,
                        end: end as u32,
                        style: SpanStyle::MarkdownMarker,
                    });
                }
            }
        }
        SpanStyle::UnorderedListItem { level } => {
            // Find the list marker (-, *, or +) by searching in the actual text
            let expected_indent = *level as usize * 2; // 2 spaces per level

            // Search for the marker pattern in the region
            if let Some(marker_pos) = region.find(['-', '*', '+']) {
                // Verify the marker is at the expected indentation
                let spaces_before = region[..marker_pos].chars().filter(|c| *c == ' ').count();
                if spaces_before == expected_indent {
                    let marker_start = start + marker_pos;
                    let mut marker_end = marker_start + 1;
                    // Include the space after the marker
                    if text.get(marker_end..marker_end + 1) == Some(" ") {
                        marker_end += 1;
                    }

                    spans.push(StyledSpan {
                        start: marker_start as u32,
                        end: marker_end as u32,
                        style: SpanStyle::MarkdownMarker,
                    });
                }
            }
        }
        SpanStyle::OrderedListItem { level, number } => {
            // Find the list number by searching in the actual text
            let expected_indent = *level as usize * 2; // 2 spaces per level
            let number_str = number.to_string();

            // Search for the number pattern in the region
            if let Some(number_pos) = region.find(&number_str) {
                // Verify the number is at the expected indentation
                let spaces_before = region[..number_pos].chars().filter(|c| *c == ' ').count();
                if spaces_before == expected_indent {
                    let marker_start = start + number_pos;
                    let mut marker_end = marker_start + number_str.len();
                    // Include the period
                    if text.get(marker_end..marker_end + 1) == Some(".") {
                        marker_end += 1;
                        // Include the space after the period
                        if text.get(marker_end..marker_end + 1) == Some(" ") {
                            marker_end += 1;
                        }
                    }

                    spans.push(StyledSpan {
                        start: marker_start as u32,
                        end: marker_end as u32,
                        style: SpanStyle::MarkdownMarker,
                    });
                }
            }
        }
        SpanStyle::Blockquote => {
            // Find > markers at the start of lines
            let mut pos = start;
            for line in region.lines() {
                if line.trim_start().starts_with('>') {
                    let line_start = pos;
                    // Find the > character
                    let whitespace_len = line.len() - line.trim_start().len();
                    let marker_start = line_start + whitespace_len;
                    let mut marker_end = marker_start + 1;
                    // Include the space after >
                    if text.get(marker_end..marker_end + 1) == Some(" ") {
                        marker_end += 1;
                    }

                    spans.push(StyledSpan {
                        start: marker_start as u32,
                        end: marker_end as u32,
                        style: SpanStyle::MarkdownMarker,
                    });
                }
                pos += line.len() + 1; // +1 for newline
            }
        }
        SpanStyle::Link { .. } => {
            // Links: [text](url)
            // Find [ and ] for link text, ( and ) for URL
            if let Some(bracket_end) = region.find("](") {
                // Opening [
                spans.push(StyledSpan {
                    start: start as u32,
                    end: (start + 1) as u32,
                    style: SpanStyle::MarkdownMarker,
                });
                // ](
                spans.push(StyledSpan {
                    start: (start + bracket_end) as u32,
                    end: (start + bracket_end + 2) as u32,
                    style: SpanStyle::MarkdownMarker,
                });
                // Closing )
                if region.ends_with(')') {
                    spans.push(StyledSpan {
                        start: (end - 1) as u32,
                        end: end as u32,
                        style: SpanStyle::MarkdownMarker,
                    });
                }
            }
        }
        _ => {}
    }
}

#[derive(Debug)]
struct ListInfo {
    is_ordered: bool,
    current_number: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_bold() {
        let text = "This is **bold** text";
        let spans = render_markdown(text);

        // Should have: 1 bold span + 2 marker spans (opening and closing **)
        let bold_span = spans.iter().find(|s| matches!(s.style, SpanStyle::Bold));
        assert!(bold_span.is_some());

        let bold_span = bold_span.unwrap();
        assert_eq!(&text[bold_span.start as usize..bold_span.end as usize], "**bold**");

        // Check for marker spans
        let markers: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::MarkdownMarker))
            .collect();
        assert_eq!(markers.len(), 2); // Opening and closing **

        // Opening **
        assert_eq!(&text[markers[0].start as usize..markers[0].end as usize], "**");
        // Closing **
        assert_eq!(&text[markers[1].start as usize..markers[1].end as usize], "**");
    }

    #[test]
    fn test_render_italic() {
        let text = "This is *italic* text";
        let spans = render_markdown(text);

        let italic_span = spans.iter().find(|s| matches!(s.style, SpanStyle::Italic));
        assert!(italic_span.is_some());
    }

    #[test]
    fn test_render_strikethrough() {
        let text = "This is ~~strikethrough~~ text";
        let spans = render_markdown(text);

        let strike_span = spans.iter().find(|s| matches!(s.style, SpanStyle::Strikethrough));
        assert!(strike_span.is_some());
    }

    #[test]
    fn test_render_header() {
        let text = "# Header 1\n## Header 2";
        let spans = render_markdown(text);

        let h1 = spans.iter().find(|s| matches!(s.style, SpanStyle::Header(1)));
        let h2 = spans.iter().find(|s| matches!(s.style, SpanStyle::Header(2)));

        assert!(h1.is_some());
        assert!(h2.is_some());
    }

    #[test]
    fn test_render_list_unordered() {
        let text = "- Item 1\n- Item 2";
        let spans = render_markdown(text);

        let list_items: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::UnorderedListItem { .. }))
            .collect();

        assert_eq!(list_items.len(), 2);
    }

    #[test]
    fn test_render_list_ordered() {
        let text = "1. Item 1\n2. Item 2";
        let spans = render_markdown(text);

        let list_items: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::OrderedListItem { .. }))
            .collect();

        assert_eq!(list_items.len(), 2);
    }

    #[test]
    fn test_render_nested_formatting() {
        let text = "**bold *and italic* text**";
        let spans = render_markdown(text);

        assert!(spans.iter().any(|s| matches!(s.style, SpanStyle::Bold)));
        assert!(spans.iter().any(|s| matches!(s.style, SpanStyle::Italic)));
    }

    #[test]
    fn test_render_link() {
        let text = "[link](https://example.com)";
        let spans = render_markdown(text);

        let link_span = spans
            .iter()
            .find(|s| matches!(s.style, SpanStyle::Link { ref url } if url == "https://example.com"));

        assert!(link_span.is_some());
    }

    #[test]
    fn test_render_code() {
        let text = "This is `inline code` here";
        let spans = render_markdown(text);

        let code_span = spans.iter().find(|s| matches!(s.style, SpanStyle::Code));
        assert!(code_span.is_some());
    }

    #[test]
    fn test_render_code_block() {
        let text = "```\ncode block\n```";
        let spans = render_markdown(text);

        let code_block = spans.iter().find(|s| matches!(s.style, SpanStyle::CodeBlock));
        assert!(code_block.is_some());
    }

    #[test]
    fn test_render_blockquote() {
        let text = "> This is a quote";
        let spans = render_markdown(text);

        let quote_spans: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::Blockquote))
            .collect();

        assert!(!quote_spans.is_empty());
    }

    #[test]
    fn test_render_blockquote_multiline() {
        let text = "> First line\n> Second line";
        let spans = render_markdown(text);

        let quote_spans: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::Blockquote))
            .collect();

        assert!(!quote_spans.is_empty());
    }

    #[test]
    fn test_hybrid_mode_bold_with_markers() {
        let text = "**bold**";
        let spans = render_markdown(text);

        // Should have 3 spans: opening **, content span (full), closing **
        assert!(spans.len() >= 3);

        // Find the bold span (covers everything)
        let bold = spans.iter().find(|s| matches!(s.style, SpanStyle::Bold)).unwrap();
        assert_eq!(&text[bold.start as usize..bold.end as usize], "**bold**");

        // Find marker spans
        let markers: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::MarkdownMarker))
            .collect();
        assert_eq!(markers.len(), 2);
        assert_eq!(&text[markers[0].start as usize..markers[0].end as usize], "**");
        assert_eq!(&text[markers[1].start as usize..markers[1].end as usize], "**");
    }

    #[test]
    fn test_hybrid_mode_italic_with_markers() {
        let text = "*italic*";
        let spans = render_markdown(text);

        // Find the italic span
        let italic = spans.iter().find(|s| matches!(s.style, SpanStyle::Italic)).unwrap();
        assert_eq!(&text[italic.start as usize..italic.end as usize], "*italic*");

        // Find marker spans
        let markers: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::MarkdownMarker))
            .collect();
        assert_eq!(markers.len(), 2);
    }

    #[test]
    fn test_hybrid_mode_header_with_markers() {
        let text = "# Header";
        let spans = render_markdown(text);

        // Find the header span
        let header = spans.iter().find(|s| matches!(s.style, SpanStyle::Header(1))).unwrap();
        assert_eq!(&text[header.start as usize..header.end as usize], "# Header");

        // Find marker span (# and space)
        let markers: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::MarkdownMarker))
            .collect();
        assert_eq!(markers.len(), 1);
        assert_eq!(&text[markers[0].start as usize..markers[0].end as usize], "# ");
    }

    #[test]
    fn test_hybrid_mode_list_with_markers() {
        let text = "- Item 1";
        let spans = render_markdown(text);

        // Find the list item span
        let _list_item = spans
            .iter()
            .find(|s| matches!(s.style, SpanStyle::UnorderedListItem { .. }))
            .unwrap();

        // Find marker span (- and space)
        let markers: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::MarkdownMarker))
            .collect();
        assert_eq!(markers.len(), 1);
        assert_eq!(&text[markers[0].start as usize..markers[0].end as usize], "- ");
    }

    #[test]
    fn test_hybrid_mode_strikethrough_with_markers() {
        let text = "~~strike~~";
        let spans = render_markdown(text);

        // Find the strikethrough span
        let strike = spans
            .iter()
            .find(|s| matches!(s.style, SpanStyle::Strikethrough))
            .unwrap();
        assert_eq!(&text[strike.start as usize..strike.end as usize], "~~strike~~");

        // Find marker spans
        let markers: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::MarkdownMarker))
            .collect();
        assert_eq!(markers.len(), 2);
        assert_eq!(&text[markers[0].start as usize..markers[0].end as usize], "~~");
        assert_eq!(&text[markers[1].start as usize..markers[1].end as usize], "~~");
    }

    #[test]
    fn test_hybrid_mode_inline_code_with_markers() {
        let text = "`code`";
        let spans = render_markdown(text);

        // Find the code span
        let code = spans.iter().find(|s| matches!(s.style, SpanStyle::Code)).unwrap();
        assert_eq!(&text[code.start as usize..code.end as usize], "`code`");

        // Find marker spans (backticks)
        let markers: Vec<_> = spans
            .iter()
            .filter(|s| matches!(s.style, SpanStyle::MarkdownMarker))
            .collect();
        assert_eq!(markers.len(), 2);
        assert_eq!(&text[markers[0].start as usize..markers[0].end as usize], "`");
        assert_eq!(&text[markers[1].start as usize..markers[1].end as usize], "`");
    }
}
