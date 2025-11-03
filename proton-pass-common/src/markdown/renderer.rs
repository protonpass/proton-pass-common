use pulldown_cmark::{Event, Parser, Tag, TagEnd};

/// Represents a styled span in the rendered markdown
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StyledSpan {
    /// Start byte offset in the text
    pub start: u32,
    /// End byte offset in the text
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
    Link { url: String },
    OrderedListItem { level: u8, number: u32 },
    UnorderedListItem { level: u8 },
    Blockquote,
}

/// Render markdown text into styled spans
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
                // Inline code
                spans.push(StyledSpan {
                    start: range.start as u32,
                    end: range.end as u32,
                    style: SpanStyle::Code,
                });
            }
            _ => {}
        }
    }

    spans
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

        let bold_span = spans.iter().find(|s| matches!(s.style, SpanStyle::Bold));
        assert!(bold_span.is_some());

        let bold_span = bold_span.unwrap();
        assert_eq!(&text[bold_span.start as usize..bold_span.end as usize], "**bold**");
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
}
