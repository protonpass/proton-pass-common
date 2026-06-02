use pulldown_cmark::CowStr;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkdownDocument {
    pub nodes: Vec<MarkdownNode>,
    pub root: Vec<MarkdownNodeId>,
}

impl MarkdownDocument {
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    pub(crate) fn with_capacity(node_capacity: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(node_capacity),
            root: Vec::new(),
        }
    }

    pub fn node(&self, id: MarkdownNodeId) -> Option<&MarkdownNode> {
        self.nodes.get(id.0 as usize).filter(|node| node.id == id)
    }

    pub(crate) fn push_node(&mut self, parent: Option<MarkdownNodeId>, kind: MarkdownNodeKind) -> MarkdownNodeId {
        let id = MarkdownNodeId(self.nodes.len() as u32);
        self.nodes.push(MarkdownNode {
            id,
            parent,
            children: SmallVec::new(),
            kind,
        });

        if let Some(parent) = parent {
            if let Some(parent_node) = self.nodes.get_mut(parent.0 as usize) {
                parent_node.children.push(id);
            }
        } else {
            self.root.push(id);
        }

        id
    }

    pub(crate) fn append_text_to_last_child(&mut self, parent: Option<MarkdownNodeId>, text: &str) -> bool {
        let last_child = match parent {
            Some(parent) => self
                .nodes
                .get(parent.0 as usize)
                .and_then(|parent_node| parent_node.children.last().copied()),
            None => self.root.last().copied(),
        };

        let Some(last_child) = last_child else {
            return false;
        };

        let Some(last_child_node) = self.nodes.get_mut(last_child.0 as usize) else {
            return false;
        };

        if let MarkdownNodeKind::Text(existing) = &mut last_child_node.kind {
            existing.push_str(text);
            return true;
        }

        false
    }

    pub(crate) fn node_mut(&mut self, id: MarkdownNodeId) -> Option<&mut MarkdownNode> {
        self.nodes.get_mut(id.0 as usize).filter(|node| node.id == id)
    }
}

impl Default for MarkdownDocument {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkdownNode {
    pub id: MarkdownNodeId,
    pub parent: Option<MarkdownNodeId>,
    pub children: SmallVec<[MarkdownNodeId; 2]>,
    pub kind: MarkdownNodeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkdownNodeId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkdownNodeKind {
    Paragraph,
    Heading {
        level: u8,
    },
    Text(String),
    Strong,
    Emphasis,
    Strikethrough,
    InlineCode(String),
    CodeBlock {
        language: Option<String>,
        code: String,
    },
    Link {
        destination: MarkdownLink,
        title: Option<String>,
    },
    Blockquote,
    OrderedList {
        start: u32,
    },
    UnorderedList,
    ListItem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkdownLink {
    Safe {
        href: String,
        scheme: MarkdownLinkScheme,
    },
    Unsafe {
        raw: String,
        reason: MarkdownUnsafeLinkReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkdownLinkScheme {
    Http,
    Https,
    Mailto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkdownUnsafeLinkReason {
    Empty,
    UnsupportedScheme,
    ControlCharacter,
    UserInfo,
    RelativeOrFragment,
    Malformed,
}

pub fn classify_markdown_link(raw: &str) -> MarkdownLink {
    let trimmed = raw.trim();
    classify_markdown_link_with_owned(trimmed, || trimmed.to_string())
}

pub(crate) fn classify_markdown_link_cow(raw: CowStr<'_>) -> MarkdownLink {
    let trimmed = raw.trim();
    let already_trimmed = trimmed.len() == raw.len();

    if trimmed.is_empty() {
        return MarkdownLink::Unsafe {
            raw: String::new(),
            reason: MarkdownUnsafeLinkReason::Empty,
        };
    }

    if trimmed.chars().any(|ch| ch.is_control()) {
        return MarkdownLink::Unsafe {
            raw: cow_into_trimmed_string(raw, already_trimmed),
            reason: MarkdownUnsafeLinkReason::ControlCharacter,
        };
    }

    let colon_pos = trimmed.as_bytes().iter().position(|byte| *byte == b':');
    if contains_percent_encoded_colon_before_scheme_separator(trimmed, colon_pos) {
        return MarkdownLink::Unsafe {
            raw: cow_into_trimmed_string(raw, already_trimmed),
            reason: MarkdownUnsafeLinkReason::Malformed,
        };
    }

    let Some(colon_pos) = colon_pos else {
        return MarkdownLink::Unsafe {
            raw: cow_into_trimmed_string(raw, already_trimmed),
            reason: MarkdownUnsafeLinkReason::RelativeOrFragment,
        };
    };

    if trimmed.starts_with('#') || colon_pos == 0 {
        return MarkdownLink::Unsafe {
            raw: cow_into_trimmed_string(raw, already_trimmed),
            reason: MarkdownUnsafeLinkReason::RelativeOrFragment,
        };
    }

    let Some(scheme) = classify_scheme(&trimmed[..colon_pos]) else {
        return MarkdownLink::Unsafe {
            raw: cow_into_trimmed_string(raw, already_trimmed),
            reason: MarkdownUnsafeLinkReason::UnsupportedScheme,
        };
    };

    let Ok(url) = Url::parse(trimmed) else {
        return MarkdownLink::Unsafe {
            raw: cow_into_trimmed_string(raw, already_trimmed),
            reason: MarkdownUnsafeLinkReason::Malformed,
        };
    };

    if !url.username().is_empty() || url.password().is_some() {
        return MarkdownLink::Unsafe {
            raw: cow_into_trimmed_string(raw, already_trimmed),
            reason: MarkdownUnsafeLinkReason::UserInfo,
        };
    }

    if matches!(scheme, MarkdownLinkScheme::Mailto) && mailto_path_has_credentials(url.path()) {
        return MarkdownLink::Unsafe {
            raw: cow_into_trimmed_string(raw, already_trimmed),
            reason: MarkdownUnsafeLinkReason::UserInfo,
        };
    }

    MarkdownLink::Safe {
        href: cow_into_trimmed_string(raw, already_trimmed),
        scheme,
    }
}

fn classify_markdown_link_with_owned(trimmed: &str, into_owned: impl FnOnce() -> String) -> MarkdownLink {
    if trimmed.is_empty() {
        return MarkdownLink::Unsafe {
            raw: String::new(),
            reason: MarkdownUnsafeLinkReason::Empty,
        };
    }

    if trimmed.chars().any(|ch| ch.is_control()) {
        return MarkdownLink::Unsafe {
            raw: into_owned(),
            reason: MarkdownUnsafeLinkReason::ControlCharacter,
        };
    }

    let colon_pos = trimmed.as_bytes().iter().position(|byte| *byte == b':');
    if contains_percent_encoded_colon_before_scheme_separator(trimmed, colon_pos) {
        return MarkdownLink::Unsafe {
            raw: into_owned(),
            reason: MarkdownUnsafeLinkReason::Malformed,
        };
    }

    let Some(colon_pos) = colon_pos else {
        return MarkdownLink::Unsafe {
            raw: into_owned(),
            reason: MarkdownUnsafeLinkReason::RelativeOrFragment,
        };
    };

    if trimmed.starts_with('#') || colon_pos == 0 {
        return MarkdownLink::Unsafe {
            raw: into_owned(),
            reason: MarkdownUnsafeLinkReason::RelativeOrFragment,
        };
    }

    let Some(scheme) = classify_scheme(&trimmed[..colon_pos]) else {
        return MarkdownLink::Unsafe {
            raw: into_owned(),
            reason: MarkdownUnsafeLinkReason::UnsupportedScheme,
        };
    };

    let Ok(url) = Url::parse(trimmed) else {
        return MarkdownLink::Unsafe {
            raw: into_owned(),
            reason: MarkdownUnsafeLinkReason::Malformed,
        };
    };

    if !url.username().is_empty() || url.password().is_some() {
        return MarkdownLink::Unsafe {
            raw: into_owned(),
            reason: MarkdownUnsafeLinkReason::UserInfo,
        };
    }

    if matches!(scheme, MarkdownLinkScheme::Mailto) && mailto_path_has_credentials(url.path()) {
        return MarkdownLink::Unsafe {
            raw: into_owned(),
            reason: MarkdownUnsafeLinkReason::UserInfo,
        };
    }

    MarkdownLink::Safe {
        href: into_owned(),
        scheme,
    }
}

fn mailto_path_has_credentials(path: &str) -> bool {
    // mailto: URLs are opaque (no authority), so the url crate won't populate
    // username/password. Detect the pattern user:pass@host manually. This also
    // rejects rare quoted local parts containing ':' before '@' by design.
    if let Some(at_pos) = path.find('@') {
        path[..at_pos].contains(':')
    } else {
        false
    }
}

fn cow_into_trimmed_string(raw: CowStr<'_>, already_trimmed: bool) -> String {
    if already_trimmed {
        raw.into_string()
    } else {
        raw.trim().to_string()
    }
}

fn contains_percent_encoded_colon_before_scheme_separator(text: &str, colon_pos: Option<usize>) -> bool {
    match colon_pos {
        Some(pos) => contains_percent_encoded_colon(&text[..pos]),
        None => contains_percent_encoded_colon(text),
    }
}

fn contains_percent_encoded_colon(text: &str) -> bool {
    text.as_bytes()
        .windows(3)
        .any(|window| window[0] == b'%' && window[1] == b'3' && window[2].eq_ignore_ascii_case(&b'a'))
}

fn classify_scheme(scheme: &str) -> Option<MarkdownLinkScheme> {
    if scheme.eq_ignore_ascii_case("http") {
        Some(MarkdownLinkScheme::Http)
    } else if scheme.eq_ignore_ascii_case("https") {
        Some(MarkdownLinkScheme::Https)
    } else if scheme.eq_ignore_ascii_case("mailto") {
        Some(MarkdownLinkScheme::Mailto)
    } else {
        None
    }
}
