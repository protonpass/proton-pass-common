use std::ops::Range;

use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};

use super::document::{classify_markdown_link_cow, MarkdownDocument, MarkdownNodeId, MarkdownNodeKind};
use super::utf16::build_utf8_to_utf16_table;
use super::{MarkdownError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkdownParseLimits {
    pub max_input_bytes: usize,
    pub max_nodes: usize,
    pub max_block_depth: usize,
    pub max_inline_depth: usize,
    pub max_link_url_bytes: usize,
    pub max_link_title_bytes: usize,
    pub max_code_block_bytes: usize,
    pub max_emitted_text_bytes: usize,
}

impl Default for MarkdownParseLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 256 * 1024,
            max_nodes: 20_000,
            max_block_depth: 32,
            max_inline_depth: 32,
            max_link_url_bytes: 2_048,
            max_link_title_bytes: 512,
            max_code_block_bytes: 128 * 1024,
            max_emitted_text_bytes: 512 * 1024,
        }
    }
}

pub fn parse_markdown_document(text: &str) -> Result<MarkdownDocument> {
    parse_markdown_document_with_limits(text, MarkdownParseLimits::default())
}

pub fn parse_markdown_document_with_limits(text: &str, limits: MarkdownParseLimits) -> Result<MarkdownDocument> {
    if text.len() > limits.max_input_bytes {
        return Err(MarkdownError::DocumentTooLarge(format!(
            "Markdown input is {} bytes, maximum is {}",
            text.len(),
            limits.max_input_bytes
        )));
    }

    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(text, options);

    let mut builder = DocumentBuilder::new(limits, estimate_node_capacity(text.len(), limits.max_nodes));

    for (event, range) in parser.into_offset_iter() {
        match event {
            Event::Start(tag) => builder.start(tag, range)?,
            Event::End(tag_end) => builder.end(tag_end),
            Event::Text(text) => builder.text_event(text, range)?,
            Event::Code(code) => builder.inline_code(code, range)?,
            Event::Html(html) | Event::InlineHtml(html) => builder.html_text_event(html, range)?,
            Event::SoftBreak => builder.text("\n", range)?,
            Event::HardBreak => builder.text("\n", range)?,
            Event::Rule => builder.thematic_break(range)?,
            Event::FootnoteReference(reference) => builder.text(reference.as_ref(), range)?,
            Event::TaskListMarker(checked) => builder.text(if checked { "[x] " } else { "[ ] " }, range)?,
            Event::InlineMath(math) | Event::DisplayMath(math) => builder.text(math.as_ref(), range)?,
        }
    }

    let mut document = builder.document;
    // Node start/end are collected as UTF-8 byte offsets (what pulldown-cmark reports), but every
    // other cursor-facing API in this module (MarkdownEditor::get_cursor/set_cursor/set_selection)
    // works in UTF-16 code units, since that's what Kotlin/Swift/JS callers index strings with.
    // Convert here so callers never have to reconcile two different offset spaces.
    // Build the offset table once (O(text.len())) rather than rescanning from byte 0 for every
    // node, which would be O(nodes * text.len()) and noticeably slow on large documents.
    let utf16_table = build_utf8_to_utf16_table(text);
    for node in document.nodes.iter_mut() {
        node.start = utf16_table[node.start as usize];
        node.end = utf16_table[node.end as usize];
    }

    Ok(document)
}

struct DocumentBuilder {
    document: MarkdownDocument,
    stack: Vec<MarkdownNodeId>,
    limits: MarkdownParseLimits,
    emitted_text_bytes: usize,
    block_depth: usize,
    inline_depth: usize,
    merge_next_text: bool,
    ignored_end_tags: Vec<TagEnd>,
}

enum ParsedStart {
    Supported(MarkdownNodeKind),
    Ignored(TagEnd),
    IgnoredWithoutEnd,
}

impl DocumentBuilder {
    fn new(limits: MarkdownParseLimits, estimated_nodes: usize) -> Self {
        Self {
            document: MarkdownDocument::with_capacity(estimated_nodes),
            stack: Vec::new(),
            limits,
            emitted_text_bytes: 0,
            block_depth: 0,
            inline_depth: 0,
            merge_next_text: false,
            ignored_end_tags: Vec::new(),
        }
    }

    fn start(&mut self, tag: Tag<'_>, range: Range<usize>) -> Result<()> {
        self.merge_next_text = false;
        let kind = match self.kind_for_start(tag)? {
            ParsedStart::Supported(kind) => kind,
            ParsedStart::Ignored(tag_end) => {
                self.ignored_end_tags.push(tag_end);
                return Ok(());
            }
            ParsedStart::IgnoredWithoutEnd => return Ok(()),
        };

        if self.is_block_kind(&kind) {
            self.block_depth += 1;
            self.check_depth()?;
        } else {
            self.inline_depth += 1;
            self.check_depth()?;
        }

        self.push_container(kind, range)
    }

    fn end(&mut self, tag_end: TagEnd) {
        self.merge_next_text = false;
        if matches!(tag_end, TagEnd::HtmlBlock) {
            return;
        }

        if self.ignored_end_tags.last().is_some_and(|ignored| *ignored == tag_end) {
            self.ignored_end_tags.pop();
            return;
        }

        if let Some(id) = self.stack.pop() {
            if let Some(node) = self.document.node(id) {
                if self.is_block_kind(&node.kind) {
                    self.block_depth = self.block_depth.saturating_sub(1);
                } else {
                    self.inline_depth = self.inline_depth.saturating_sub(1);
                }
            }
        }
    }

    fn text(&mut self, text: &str, range: Range<usize>) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }

        if let Some(code_block) = self.current_code_block() {
            return self.append_code_block_text(code_block, text, range.end as u32);
        }

        self.add_emitted_text(text.len())?;
        self.push_text_node(text.to_string(), false, false, range)
    }

    fn text_event(&mut self, text: CowStr<'_>, range: Range<usize>) -> Result<()> {
        self.text_cow(text, self.merge_next_text, self.merge_next_text, range)
    }

    fn html_text_event(&mut self, text: CowStr<'_>, range: Range<usize>) -> Result<()> {
        self.text_cow(text, true, true, range)
    }

    fn text_cow(
        &mut self,
        text: CowStr<'_>,
        merge_with_previous: bool,
        merge_following_text: bool,
        range: Range<usize>,
    ) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }

        if let Some(code_block) = self.current_code_block() {
            return self.append_code_block_text(code_block, text.as_ref(), range.end as u32);
        }

        self.add_emitted_text(text.len())?;
        if merge_with_previous {
            let parent = self.stack.last().copied();
            if self
                .document
                .append_text_to_last_child(parent, text.as_ref(), range.end as u32)
            {
                self.merge_next_text = merge_following_text;
                return Ok(());
            }
        }
        self.push_text_node(text.into_string(), false, merge_following_text, range)
    }

    fn push_text_node(
        &mut self,
        text: String,
        merge_with_previous: bool,
        merge_following_text: bool,
        range: Range<usize>,
    ) -> Result<()> {
        let parent = self.stack.last().copied();
        if merge_with_previous && self.document.append_text_to_last_child(parent, &text, range.end as u32) {
            self.merge_next_text = merge_following_text;
            return Ok(());
        }
        self.check_node_budget()?;
        self.document.push_node(
            parent,
            MarkdownNodeKind::Text(text),
            range.start as u32,
            range.end as u32,
        );
        self.merge_next_text = merge_following_text;
        Ok(())
    }

    fn inline_code(&mut self, code: CowStr<'_>, range: Range<usize>) -> Result<()> {
        self.merge_next_text = false;
        self.add_emitted_text(code.len())?;
        self.push_leaf(MarkdownNodeKind::InlineCode(code.into_string()), range)
    }

    fn kind_for_start(&self, tag: Tag<'_>) -> Result<ParsedStart> {
        let kind = match tag {
            Tag::Paragraph => MarkdownNodeKind::Paragraph,
            Tag::Heading { level, .. } => MarkdownNodeKind::Heading { level: level as u8 },
            Tag::BlockQuote(_) => MarkdownNodeKind::Blockquote,
            Tag::CodeBlock(kind) => {
                let language = match kind {
                    CodeBlockKind::Fenced(language) if !language.is_empty() => Some(language.to_string()),
                    _ => None,
                };
                MarkdownNodeKind::CodeBlock {
                    language,
                    code: String::new(),
                }
            }
            Tag::HtmlBlock => return Ok(ParsedStart::IgnoredWithoutEnd),
            Tag::List(start) => match start {
                // pulldown-cmark follows CommonMark's ordered-list marker
                // grammar, so oversized numeric markers are paragraph text
                // instead of Tag::List values.
                Some(start) => MarkdownNodeKind::OrderedList { start: start as u32 },
                None => MarkdownNodeKind::UnorderedList,
            },
            Tag::Item => MarkdownNodeKind::ListItem,
            Tag::Emphasis => MarkdownNodeKind::Emphasis,
            Tag::Strong => MarkdownNodeKind::Strong,
            Tag::Strikethrough => MarkdownNodeKind::Strikethrough,
            Tag::Link { dest_url, title, .. } => {
                if dest_url.len() > self.limits.max_link_url_bytes {
                    return Err(MarkdownError::PayloadTooLarge(format!(
                        "Link URL is {} bytes, maximum is {}",
                        dest_url.len(),
                        self.limits.max_link_url_bytes
                    )));
                }
                if title.len() > self.limits.max_link_title_bytes {
                    return Err(MarkdownError::PayloadTooLarge(format!(
                        "Link title is {} bytes, maximum is {}",
                        title.len(),
                        self.limits.max_link_title_bytes
                    )));
                }
                MarkdownNodeKind::Link {
                    destination: classify_markdown_link_cow(dest_url),
                    title: if title.is_empty() {
                        None
                    } else {
                        Some(title.into_string())
                    },
                }
            }
            Tag::Image { .. } => return Ok(ParsedStart::Ignored(TagEnd::Image)),
            Tag::FootnoteDefinition(_) => return Ok(ParsedStart::Ignored(TagEnd::FootnoteDefinition)),
            Tag::DefinitionList => return Ok(ParsedStart::Ignored(TagEnd::DefinitionList)),
            Tag::DefinitionListTitle => return Ok(ParsedStart::Ignored(TagEnd::DefinitionListTitle)),
            Tag::DefinitionListDefinition => return Ok(ParsedStart::Ignored(TagEnd::DefinitionListDefinition)),
            Tag::Table(_) => return Ok(ParsedStart::Ignored(TagEnd::Table)),
            Tag::TableHead => return Ok(ParsedStart::Ignored(TagEnd::TableHead)),
            Tag::TableRow => return Ok(ParsedStart::Ignored(TagEnd::TableRow)),
            Tag::TableCell => return Ok(ParsedStart::Ignored(TagEnd::TableCell)),
            Tag::Superscript => return Ok(ParsedStart::Ignored(TagEnd::Superscript)),
            Tag::Subscript => return Ok(ParsedStart::Ignored(TagEnd::Subscript)),
            Tag::MetadataBlock(kind) => return Ok(ParsedStart::Ignored(TagEnd::MetadataBlock(kind))),
        };

        Ok(ParsedStart::Supported(kind))
    }

    fn push_container(&mut self, kind: MarkdownNodeKind, range: Range<usize>) -> Result<()> {
        self.check_node_budget()?;
        let parent = self.stack.last().copied();
        let id = self
            .document
            .push_node(parent, kind, range.start as u32, range.end as u32);
        self.stack.push(id);
        Ok(())
    }

    fn push_leaf(&mut self, kind: MarkdownNodeKind, range: Range<usize>) -> Result<()> {
        self.check_node_budget()?;
        let parent = self.stack.last().copied();
        self.document
            .push_node(parent, kind, range.start as u32, range.end as u32);
        Ok(())
    }

    fn current_code_block(&self) -> Option<MarkdownNodeId> {
        self.stack.last().copied().filter(|id| {
            self.document
                .node(*id)
                .is_some_and(|node| matches!(node.kind, MarkdownNodeKind::CodeBlock { .. }))
        })
    }

    fn append_code_block_text(&mut self, code_block: MarkdownNodeId, text: &str, end: u32) -> Result<()> {
        let new_len = match &self.document.node(code_block).map(|node| &node.kind) {
            Some(MarkdownNodeKind::CodeBlock { code, .. }) => code.len() + text.len(),
            _ => text.len(),
        };
        if new_len > self.limits.max_code_block_bytes {
            return Err(MarkdownError::PayloadTooLarge(format!(
                "Code block is {} bytes, maximum is {}",
                new_len, self.limits.max_code_block_bytes
            )));
        }
        if let Some(node) = self.document.node_mut(code_block) {
            if let MarkdownNodeKind::CodeBlock { code, .. } = &mut node.kind {
                code.push_str(text);
            }
            node.end = node.end.max(end);
        }
        self.add_emitted_text(text.len())
    }

    fn add_emitted_text(&mut self, len: usize) -> Result<()> {
        self.emitted_text_bytes += len;
        if self.emitted_text_bytes > self.limits.max_emitted_text_bytes {
            return Err(MarkdownError::PayloadTooLarge(format!(
                "Emitted text is {} bytes, maximum is {}",
                self.emitted_text_bytes, self.limits.max_emitted_text_bytes
            )));
        }
        Ok(())
    }

    fn check_node_budget(&self) -> Result<()> {
        if self.document.nodes.len() >= self.limits.max_nodes {
            return Err(MarkdownError::TooManyNodes(format!(
                "Markdown document has more than {} nodes",
                self.limits.max_nodes
            )));
        }
        Ok(())
    }

    fn check_depth(&self) -> Result<()> {
        if self.block_depth > self.limits.max_block_depth {
            return Err(MarkdownError::TooDeep(format!(
                "Markdown block depth exceeds {}",
                self.limits.max_block_depth
            )));
        }
        if self.inline_depth > self.limits.max_inline_depth {
            return Err(MarkdownError::TooDeep(format!(
                "Markdown inline depth exceeds {}",
                self.limits.max_inline_depth
            )));
        }
        Ok(())
    }

    fn thematic_break(&mut self, range: Range<usize>) -> Result<()> {
        self.check_node_budget()?;
        self.push_leaf(MarkdownNodeKind::ThematicBreak, range)
    }

    fn is_block_kind(&self, kind: &MarkdownNodeKind) -> bool {
        matches!(
            kind,
            MarkdownNodeKind::Paragraph
                | MarkdownNodeKind::Heading { .. }
                | MarkdownNodeKind::CodeBlock { .. }
                | MarkdownNodeKind::Blockquote
                | MarkdownNodeKind::OrderedList { .. }
                | MarkdownNodeKind::UnorderedList
                | MarkdownNodeKind::ListItem
                | MarkdownNodeKind::ThematicBreak
        )
    }
}

fn estimate_node_capacity(input_bytes: usize, max_nodes: usize) -> usize {
    // Most supported markdown constructs consume several bytes per emitted node.
    // Keep the reserve intentionally modest and only use it for smaller inputs:
    // large up-front allocations regress node-heavy documents more than they
    // save in Vec growth.
    if input_bytes > 4 * 1024 {
        return 0;
    }

    let estimated = (input_bytes / 16).saturating_add(8).min(128);
    estimated.min(max_nodes)
}
