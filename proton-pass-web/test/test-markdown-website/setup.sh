#!/bin/bash

# Setup script for the markdown editor test website
# This script builds the WASM module and copies it to the website directory

set -e

echo "🚀 Setting up Markdown Editor Test Website..."
echo ""

# Check if we're in the right directory
if [ ! -f "index.html" ]; then
    echo "❌ Error: Please run this script from the test-markdown-website directory"
    exit 1
fi

# Navigate to proton-pass-web root
cd ../../

echo "📦 Building WASM module (web_ui feature) for browser..."
# Build with --target web for browser compatibility (not nodejs!)
wasm-pack build --scope protontech --target web --out-dir test/pkg-temp/ui --features "web_ui"

echo "📋 Copying artifacts to website directory..."
# Copy to the website's pkg directory
rm -rf test/test-markdown-website/pkg
mkdir -p test/test-markdown-website/pkg/ui
cp -R test/pkg-temp/ui/* test/test-markdown-website/pkg/ui/

echo "🧹 Cleaning up temporary build directory..."
rm -rf test/pkg-temp

echo ""
echo "✅ Build complete!"
echo ""
echo "🌐 To start the test website:"
echo ""
echo "  Option 1 (Python):"
echo "    cd test/test-markdown-website"
echo "    python3 -m http.server 8000"
echo ""
echo "  Option 2 (Node.js):"
echo "    cd test/test-markdown-website"
echo "    npx http-server -p 8000"
echo ""
echo "  Then open: http://localhost:8000"
echo ""

