# Markdown

Shared Markdown editing and rendering lives in `proton-pass-common` so web, Android, and iOS use the same parser contracts and safety decisions.

## APIs

- `MarkdownEditor` is the editing surface. Public text offsets are UTF-16 code units for platform compatibility; internally the editor stores UTF-8 byte offsets.
- `render_editor_spans(text)` and `MarkdownEditor::render_editor_spans()` return source-overlay spans for editor UIs. They keep Markdown markers visible and export UTF-16 span offsets.
- `parse_markdown_document(text)` returns the platform-neutral display IR for read-only rendering. Platforms should render this IR with native UI primitives or DOM node creation, not raw HTML.

## Display IR

`MarkdownDocument` is a flat node table:

- `nodes`: all nodes in document order, each with stable `MarkdownNodeId`.
- `root`: top-level node ids.
- each `MarkdownNode` stores `parent`, `children`, and `MarkdownNodeKind`.

The IR supports paragraphs, headings, text, emphasis, strong, strikethrough, inline code, fenced code blocks, links, blockquotes, ordered lists, unordered lists, and list items.

Raw HTML is represented as text. For example, `Click <kbd>Enter</kbd>` renders the literal `<kbd>` markup unless a platform product decision adds trusted HTML support later.

## Link Safety

All link classification is shared Rust logic:

- safe schemes: `http`, `https`, `mailto`
- unsupported schemes such as `javascript:`, `data:`, `tel:`, and `sms:` are unsafe in v1
- bare fragments and relative links are unsafe in v1
- `http` and `https` links containing userinfo are unsafe
- control characters and malformed URLs are unsafe
- `mailto:` validation is scheme-level only in v1

`MarkdownLink::Safe { href, scheme }` preserves the user's trimmed href for display/navigation and includes the parsed scheme as convenience data. `MarkdownLink::Unsafe { raw, reason }` preserves the trimmed raw destination; whitespace-only links use an empty raw string with reason `Empty`.

Callers must handle every parser error and render fallback UI when parsing fails.

## Parser Budgets

Default `MarkdownParseLimits`:

- input: 256 KiB
- nodes: 20,000
- block depth: 32
- inline depth: 32
- link destination: 2,048 bytes
- link title: 512 bytes
- code block: 128 KiB
- emitted text: 512 KiB

These limits are enforced before platform bindings receive a document. If production note corpus data shows legitimate notes hitting a limit, update the fixture corpus and recalibrate the defaults before raising them.

## Editing Contracts

- Unordered list continuation normalizes `* item` to `- ` for the next line.
- Ordered list continuation uses the immediate previous list marker number plus one and does not renumber following list items.
- Tab-prefixed list markers are plain text in v1. They must not panic, but they do not trigger smart list continuation.
- Header and blockquote operations apply to the line containing the cursor or the selection start in v1.
- Empty no-op formatting operations must not create undo entries.

## Platform Bindings

- Web exports `parseMarkdownDocument(text)` and `MarkdownEditor.renderEditorSpans()`. It intentionally does not export raw HTML rendering.
- Mobile exports `parse_markdown_document(text)` and `MarkdownEditor.render_editor_spans()` through UniFFI.
- Mobile wrapper methods must not panic on poisoned locks; fallible methods return `MarkdownError::InvalidOperation`, and read-only helpers return safe defaults.

## Verification

Useful focused checks:

```bash
rtk cargo test -p proton-pass-common markdown --lib
rtk cargo test -p proton-pass-mobile
rtk make web-test
rtk cargo bench -p proton-pass-common --bench markdown_renderer
```
