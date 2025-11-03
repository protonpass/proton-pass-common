# Proton Pass Markdown Editor Test Website

A beautiful WYSIWYG markdown editor powered by Rust + WASM to test the Proton Pass markdown library.

## 🚀 Quick Start

### 1. Build the WASM Module

From the `proton-pass-web/test` directory:

```bash
# Build the UI module (includes markdown editor)
cd ../../
wasm-pack build --features web_ui --target nodejs --out-dir test/pkg/ui --out-name proton_pass_web
cd test
```

Or use the build script if available:

```bash
cd ../
make web-build
cd test/test-markdown-website
```

### 2. Serve the Website

You can use any static file server. Here are some options:

#### Option A: Python (simplest)
```bash
# Python 3
python3 -m http.server 8000

# Python 2
python -m SimpleHTTPServer 8000
```

#### Option B: Node.js
```bash
# Install globally if you don't have it
npm install -g http-server

# Run
http-server -p 8000
```

#### Option C: PHP
```bash
php -S localhost:8000
```

### 3. Open in Browser

Navigate to: http://localhost:8000

## ✨ Features

### Editor Features
- **Real-time Preview**: See HTML output as you type
- **Formatting Toolbar**: Quick access to all markdown operations
- **Keyboard Shortcuts**: 
  - `Ctrl+B` / `Cmd+B` - Bold
  - `Ctrl+I` / `Cmd+I` - Italic
  - `Ctrl+Z` / `Cmd+Z` - Undo
  - `Ctrl+Y` / `Cmd+Y` - Redo

### Supported Markdown
- **Inline Formatting**: Bold, Italic, Strikethrough
- **Headers**: H1 through H6
- **Lists**: Ordered, unordered, and nested
- **Code**: Inline and code blocks
- **Links**: Full link support with URLs
- **Smart List Continuation**: Press Enter to auto-continue lists

### Information Panel
- Character and word count
- Current selection info
- Undo/redo state
- Styled spans visualization

## 🎨 UI Components

### Editor Pane
- **Textarea**: Write your markdown
- **Raw Markdown Display**: See the plain text with syntax

### Preview Pane
- **HTML Preview**: Rendered HTML output
- **Raw HTML**: Toggle to see the generated HTML code

### Toolbar
Buttons for all markdown operations:
- Bold, Italic, Strikethrough
- Headers (H1, H2, H3)
- Lists (Unordered, Ordered, Indent, Unindent)
- Undo/Redo
- Clear

## 🧪 Testing

Use this website to:
1. Test all markdown operations
2. Verify Unicode and emoji handling
3. Test undo/redo functionality
4. Verify HTML rendering
5. Test keyboard shortcuts
6. Share with teammates for feedback

## 📦 Deployment

To share with teammates:

### Option 1: GitHub Pages
1. Commit the files to a repository
2. Build the WASM module and copy `pkg/` directory
3. Enable GitHub Pages on the repository
4. Share the URL

### Option 2: Netlify/Vercel
1. Build the WASM module
2. Upload the entire directory
3. Share the generated URL

### Option 3: Internal Server
1. Build the WASM module
2. Copy all files to your web server
3. Share the internal URL

## 🔧 Development

To modify the website:

1. **HTML**: Edit `index.html` for structure
2. **CSS**: Edit `styles.css` for styling  
3. **JavaScript**: Edit `script.js` for functionality

After making changes, refresh your browser to see updates.

## 🐛 Troubleshooting

### "Failed to Load" Error

Make sure you've built the WASM module first:
```bash
cd ../..
wasm-pack build --features web_ui --target nodejs --out-dir test/pkg/ui --out-name proton_pass_web
```

### CORS Errors

Make sure you're serving the files through HTTP (not opening them directly via file://).

### Module Not Found

Check that the `pkg/ui` directory exists in the parent `test` directory with the WASM files.

## 📝 Notes

- The editor uses UTF-8 byte positions internally (for Rust compatibility)
- Emoji and Unicode characters are fully supported
- Undo stack is limited to 100 operations
- All operations are processed client-side (no server required)

