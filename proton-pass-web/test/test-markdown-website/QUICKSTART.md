# ⚡ Quick Start Guide

## 🎯 For First-Time Users

### Step 1: Build the WASM module

```bash
./setup.sh
```

### Step 2: Start the server

```bash
python3 -m http.server 8000
```

### Step 3: Open in browser

Visit: **http://localhost:8000**

---

## 🎨 How to Use the Editor

### Formatting Text

1. **Select text** you want to format
2. **Click a toolbar button** (or use keyboard shortcuts)
3. **See the result** in real-time!

### Keyboard Shortcuts

| Action | Shortcut (Mac) | Shortcut (Windows) |
|--------|---------------|-------------------|
| Bold | `Cmd+B` | `Ctrl+B` |
| Italic | `Cmd+I` | `Ctrl+I` |
| Undo | `Cmd+Z` | `Ctrl+Z` |
| Redo | `Cmd+Shift+Z` | `Ctrl+Y` |

### Features to Test

✅ **Inline Formatting**
- Select text and click Bold (**B**)
- Select text and click Italic (*I*)
- Select text and click Strikethrough (~~S~~)

✅ **Headers**
- Click H1, H2, or H3 buttons
- Header applied to current line

✅ **Lists**
- Select multiple lines
- Click bullet or numbered list
- Use indent/unindent to nest

✅ **Smart Features**
- Press Enter in a list → auto-continues the list
- Press Enter twice → exits the list
- Full undo/redo support

---

## 🐛 Troubleshooting

### "Failed to Load" Error?

Run the setup script again:
```bash
./setup.sh
```

### Nothing happens when I click buttons?

Check the browser console (F12) for errors.

### Want to rebuild?

```bash
# Clean and rebuild
rm -rf ../pkg/ui
./setup.sh
```

---

## 📤 Sharing with Teammates

### Option 1: Share Locally (Same Network)

```bash
# Find your local IP
# Mac/Linux:
ifconfig | grep "inet " | grep -v 127.0.0.1

# Then start server:
python3 -m http.server 8000

# Share: http://YOUR_IP:8000
```

### Option 2: Deploy to a Server

See the main README.md for deployment options.

---

## 💡 Tips

- **Preview pane** shows the HTML output
- **Toggle** between HTML view and raw HTML code
- **Info panel** shows current editor state
- **Spans section** shows detected formatting
- **Character/word count** updates in real-time

---

## 🎯 Example Workflow

1. Type: `Hello world`
2. Select "Hello"
3. Click **B** button → becomes `**Hello** world`
4. Select "world"  
5. Click *I* button → becomes `**Hello** *world*`
6. See HTML preview: `<p><strong>Hello</strong> <em>world</em></p>`

---

Need help? Check the main [README.md](README.md) for detailed information!

