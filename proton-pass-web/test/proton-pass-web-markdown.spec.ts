import { describe, expect, test } from "bun:test";

import { MarkdownEditor } from "./pkg/ui";

describe("ProtonPassWeb Markdown WASM", () => {
    describe("Basic Editor Operations", () => {
        test("Should create editor with text", () => {
            const editor = new MarkdownEditor("hello world");
            expect(editor.getText()).toBe("hello world");
        });

        test("Should get and set cursor position", () => {
            const editor = new MarkdownEditor("hello world");
            editor.setCursor(5);
            expect(editor.getCursor()).toBe(5);
        });

        test("Should set selection", () => {
            const editor = new MarkdownEditor("hello world");
            editor.setSelection(0, 5);
            // Selection is set, no error thrown
            expect(editor.getText()).toBe("hello world");
        });

        test("Should throw on invalid cursor position", () => {
            const editor = new MarkdownEditor("hello");
            expect(() => editor.setCursor(100)).toThrow();
        });
    });

    describe("Bold Operation", () => {
        test("Should apply bold to selection", () => {
            const editor = new MarkdownEditor("hello world");
            editor.setSelection(0, 5);
            editor.applyOperation("bold");
            expect(editor.getText()).toBe("**hello** world");
        });

        test("Should remove bold from selection", () => {
            const editor = new MarkdownEditor("**hello** world");
            editor.setSelection(2, 7); // Select "hello" inside **
            editor.applyOperation("bold");
            expect(editor.getText()).toBe("hello world");
        });

        test("Should bold word at cursor", () => {
            const editor = new MarkdownEditor("hello world test");
            editor.setCursor(8); // In "world"
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**world**");
        });
    });

    describe("Italic Operation", () => {
        test("Should apply italic to selection", () => {
            const editor = new MarkdownEditor("hello world");
            editor.setSelection(6, 11);
            editor.applyOperation("italic");
            expect(editor.getText()).toBe("hello *world*");
        });

        test("Should remove italic from selection", () => {
            const editor = new MarkdownEditor("hello *world*");
            editor.setSelection(7, 12); // Select "world" inside *
            editor.applyOperation("italic");
            expect(editor.getText()).toBe("hello world");
        });
    });

    describe("Strikethrough Operation", () => {
        test("Should apply strikethrough to selection", () => {
            const editor = new MarkdownEditor("hello world");
            editor.setSelection(0, 5);
            editor.applyOperation("strikethrough");
            expect(editor.getText()).toBe("~~hello~~ world");
        });

        test("Should remove strikethrough from selection", () => {
            const editor = new MarkdownEditor("~~hello~~ world");
            editor.setSelection(2, 7); // Select "hello" inside ~~
            editor.applyOperation("strikethrough");
            expect(editor.getText()).toBe("hello world");
        });
    });

    describe("Header Operations", () => {
        test("Should apply H1", () => {
            const editor = new MarkdownEditor("Title");
            editor.setCursor(3);
            editor.applyOperation("header1");
            expect(editor.getText()).toBe("# Title");
        });

        test("Should apply H2", () => {
            const editor = new MarkdownEditor("Title");
            editor.setCursor(3);
            editor.applyOperation("header2");
            expect(editor.getText()).toBe("## Title");
        });

        test("Should apply H3", () => {
            const editor = new MarkdownEditor("Title");
            editor.setCursor(3);
            editor.applyOperation("header3");
            expect(editor.getText()).toBe("### Title");
        });

        test("Should toggle header off", () => {
            const editor = new MarkdownEditor("# Title");
            editor.setCursor(4);
            editor.applyOperation("header1");
            expect(editor.getText()).toBe("Title");
        });

        test("Should change header level", () => {
            const editor = new MarkdownEditor("# Title");
            editor.setCursor(4);
            editor.applyOperation("header2");
            expect(editor.getText()).toBe("## Title");
        });
    });

    describe("List Operations", () => {
        test("Should create unordered list", () => {
            const editor = new MarkdownEditor("item 1\nitem 2\nitem 3");
            editor.setSelection(0, editor.getText().length);
            editor.applyOperation("createUnorderedList");
            
            const text = editor.getText();
            expect(text).toContain("- item 1");
            expect(text).toContain("- item 2");
            expect(text).toContain("- item 3");
        });

        test("Should create ordered list", () => {
            const editor = new MarkdownEditor("item 1\nitem 2\nitem 3");
            editor.setSelection(0, editor.getText().length);
            editor.applyOperation("createOrderedList");
            
            const text = editor.getText();
            expect(text).toContain("1. item 1");
            expect(text).toContain("2. item 2");
            expect(text).toContain("3. item 3");
        });

        test("Should toggle list off", () => {
            const editor = new MarkdownEditor("- item 1\n- item 2");
            editor.setSelection(0, editor.getText().length);
            editor.applyOperation("createUnorderedList");
            
            const text = editor.getText();
            expect(text).toContain("item 1");
            expect(text).toContain("item 2");
            expect(text).not.toContain("-");
        });

        test("Should indent list item", () => {
            const editor = new MarkdownEditor("- item 1");
            editor.setCursor(0);
            editor.applyOperation("indentList");
            expect(editor.getText()).toBe("  - item 1");
        });

        test("Should unindent list item", () => {
            const editor = new MarkdownEditor("  - item 1");
            editor.setCursor(0);
            editor.applyOperation("unindentList");
            expect(editor.getText()).toBe("- item 1");
        });

        test("Should indent multiple levels", () => {
            const editor = new MarkdownEditor("- item 1");
            editor.setCursor(0);
            editor.applyOperation("indentList");
            editor.applyOperation("indentList");
            expect(editor.getText()).toBe("    - item 1");
        });
    });

    describe("Undo/Redo", () => {
        test("Should undo bold operation", () => {
            const editor = new MarkdownEditor("hello world");
            editor.setSelection(0, 5);
            editor.applyOperation("bold");
            expect(editor.getText()).toBe("**hello** world");
            
            expect(editor.canUndo()).toBe(true);
            editor.undo();
            expect(editor.getText()).toBe("hello world");
        });

        test("Should redo bold operation", () => {
            const editor = new MarkdownEditor("hello world");
            editor.setSelection(0, 5);
            editor.applyOperation("bold");
            editor.undo();
            
            expect(editor.canRedo()).toBe(true);
            editor.redo();
            expect(editor.getText()).toBe("**hello** world");
        });

        test("Should handle undo/redo chain", () => {
            const editor = new MarkdownEditor("word1 word2 word3");
            
            // Apply bold to first word
            editor.setSelection(0, 5);
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**word1**");
            
            // Apply italic to second word
            const text1 = editor.getText();
            const word2Start = text1.indexOf("word2");
            editor.setSelection(word2Start, word2Start + 5);
            editor.applyOperation("italic");
            expect(editor.getText()).toContain("*word2*");
            
            // Apply strikethrough to third word
            const text2 = editor.getText();
            const word3Start = text2.indexOf("word3");
            editor.setSelection(word3Start, word3Start + 5);
            editor.applyOperation("strikethrough");
            expect(editor.getText()).toContain("~~word3~~");
            
            // Undo all
            editor.undo();
            editor.undo();
            editor.undo();
            expect(editor.getText()).toBe("word1 word2 word3");
            
            // Redo all
            editor.redo();
            editor.redo();
            editor.redo();
            
            const finalText = editor.getText();
            expect(finalText).toContain("**word1**");
            expect(finalText).toContain("*word2*");
            expect(finalText).toContain("~~word3~~");
        });

        test("Should clear redo stack on new operation", () => {
            const editor = new MarkdownEditor("hello");
            editor.setSelection(0, 5);
            editor.applyOperation("bold");
            editor.undo();
            
            expect(editor.canRedo()).toBe(true);
            
            // New operation should clear redo
            editor.applyOperation("italic");
            expect(editor.canRedo()).toBe(false);
        });
    });

    describe("Rendering", () => {
        test("Should render bold text", () => {
            const editor = new MarkdownEditor("**bold** text");
            const spans = editor.render();
            
            const boldSpan = spans.find(s => s.style === "bold");
            expect(boldSpan).toBeDefined();
            expect(boldSpan!.start).toBe(0);
        });

        test("Should render italic text", () => {
            const editor = new MarkdownEditor("*italic* text");
            const spans = editor.render();
            
            const italicSpan = spans.find(s => s.style === "italic");
            expect(italicSpan).toBeDefined();
        });

        test("Should render strikethrough text", () => {
            const editor = new MarkdownEditor("~~strike~~ text");
            const spans = editor.render();
            
            const strikeSpan = spans.find(s => s.style === "strikethrough");
            expect(strikeSpan).toBeDefined();
        });

        test("Should render headers", () => {
            const editor = new MarkdownEditor("# H1\n## H2\n### H3");
            const spans = editor.render();
            
            const h1 = spans.find(s => s.style === "header1");
            const h2 = spans.find(s => s.style === "header2");
            const h3 = spans.find(s => s.style === "header3");
            
            expect(h1).toBeDefined();
            expect(h2).toBeDefined();
            expect(h3).toBeDefined();
        });

        test("Should render unordered list", () => {
            const editor = new MarkdownEditor("- item 1\n- item 2");
            const spans = editor.render();
            
            const listSpans = spans.filter(s => s.style === "unorderedListItem");
            expect(listSpans.length).toBe(2);
        });

        test("Should render ordered list with numbers", () => {
            const editor = new MarkdownEditor("1. first\n2. second");
            const spans = editor.render();
            
            const listSpans = spans.filter(s => s.style === "orderedListItem");
            expect(listSpans.length).toBe(2);
            
            expect(listSpans[0].number).toBe(1);
            expect(listSpans[1].number).toBe(2);
        });

        test("Should render link with url", () => {
            const editor = new MarkdownEditor("[link](https://example.com)");
            const spans = editor.render();
            
            const linkSpan = spans.find(s => s.style === "link");
            expect(linkSpan).toBeDefined();
            expect(linkSpan!.url).toBe("https://example.com");
        });
    });

    describe("Unicode and Emoji Handling", () => {
        // Helper function to get UTF-8 byte length
        const utf8ByteLength = (str: string): number => {
            return new TextEncoder().encode(str).length;
        };

        test("Should handle simple emoji", () => {
            const editor = new MarkdownEditor("hello 👋 world");
            const start = utf8ByteLength("hello ");
            const end = utf8ByteLength("hello 👋");
            editor.setSelection(start, end);
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**👋**");
        });

        test("Should handle emoji with skin tone", () => {
            const editor = new MarkdownEditor("wave 👋🏽 here");
            const start = utf8ByteLength("wave ");
            const end = utf8ByteLength("wave 👋🏽");
            editor.setSelection(start, end);
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**👋🏽**");
        });

        test("Should handle family emoji", () => {
            const editor = new MarkdownEditor("family 👨‍👩‍👧‍👦 here");
            const start = utf8ByteLength("family ");
            const end = utf8ByteLength("family 👨‍👩‍👧‍👦");
            editor.setSelection(start, end);
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("👨‍👩‍👧‍👦");
            expect(editor.getText()).toContain("**");
        });

        test("Should handle Japanese characters", () => {
            const editor = new MarkdownEditor("こんにちは world");
            const start = 0;
            const end = utf8ByteLength("こんにちは");
            editor.setSelection(start, end);
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**こんにちは**");
        });

        test("Should handle mixed content", () => {
            const text = "Hello 世界 👋🏽!";
            const editor = new MarkdownEditor(text);
            const start = 0;
            const end = utf8ByteLength(text);
            editor.setSelection(start, end);
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**");
            expect(editor.getText()).toContain("世界");
            expect(editor.getText()).toContain("👋🏽");
        });
    });

    describe("Edge Cases", () => {
        test("Should handle empty text", () => {
            const editor = new MarkdownEditor("");
            expect(editor.getText()).toBe("");
            editor.applyOperation("bold");
            // Should not crash
            expect(editor.getText()).toBeDefined();
        });

        test("Should handle cursor at end", () => {
            const editor = new MarkdownEditor("hello");
            editor.setCursor(5);
            editor.applyOperation("bold");
            // Should handle gracefully
            expect(editor.getText()).toBeDefined();
        });

        test("Should handle multiline selection", () => {
            const editor = new MarkdownEditor("line 1\nline 2\nline 3");
            editor.setSelection(0, 20);
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**");
        });

        test("Should handle word at cursor detection", () => {
            const editor = new MarkdownEditor("the quick brown fox");
            editor.setCursor(10); // In "brown"
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**brown**");
        });

        test("Should handle cursor at end of word - bold", () => {
            const editor = new MarkdownEditor("hello world");
            editor.setCursor(5); // Right after "hello"
            editor.applyOperation("bold");
            expect(editor.getText()).toBe("**hello** world");
        });

        test("Should handle cursor at end of word - italic", () => {
            const editor = new MarkdownEditor("test item");
            editor.setCursor(4); // Right after "test"
            editor.applyOperation("italic");
            expect(editor.getText()).toBe("*test* item");
        });

        test("Should handle cursor at end of second word", () => {
            const editor = new MarkdownEditor("first second");
            editor.setCursor(12); // Right after "second"
            editor.applyOperation("bold");
            expect(editor.getText()).toBe("first **second**");
        });

        test("Should handle cursor at end of text", () => {
            const editor = new MarkdownEditor("word");
            editor.setCursor(4); // End of text
            editor.applyOperation("bold");
            expect(editor.getText()).toBe("**word**");
        });

        test("Should handle cursor at end with emoji", () => {
            const editor = new MarkdownEditor("test👋 next");
            const utf8ByteLength = (str: string) => new TextEncoder().encode(str).length;
            const emojiEnd = utf8ByteLength("test👋");
            editor.setCursor(emojiEnd); // Right after emoji
            editor.applyOperation("bold");
            expect(editor.getText()).toContain("**test👋**");
        });

        test("Should handle cursor in middle vs end consistently", () => {
            // Cursor in middle
            const editor1 = new MarkdownEditor("testing");
            editor1.setCursor(3); // Middle
            editor1.applyOperation("bold");
            
            // Cursor at end
            const editor2 = new MarkdownEditor("testing");
            editor2.setCursor(7); // End
            editor2.applyOperation("bold");
            
            // Both should produce same result
            expect(editor1.getText()).toBe("**testing**");
            expect(editor2.getText()).toBe("**testing**");
            expect(editor1.getText()).toBe(editor2.getText());
        });

        test("Should preserve content on invalid operations", () => {
            const editor = new MarkdownEditor("test text");
            const original = editor.getText();
            
            try {
                editor.setCursor(1000);
            } catch {
                // Expected to throw
            }
            
            // Text should be unchanged
            expect(editor.getText()).toBe(original);
        });
    });

    describe("Smart Newline Insertion", () => {
        test("Should auto-continue ordered list", () => {
            const editor = new MarkdownEditor("1. First item");
            editor.setCursor(13); // End of line
            editor.insertNewline();
            
            expect(editor.getText()).toBe("1. First item\n2. ");
            expect(editor.getCursor()).toBe(17);
        });

        test("Should auto-continue unordered list", () => {
            const editor = new MarkdownEditor("- First item");
            editor.setCursor(12);
            editor.insertNewline();
            
            expect(editor.getText()).toBe("- First item\n- ");
            expect(editor.getCursor()).toBe(15);
        });

        test("Should split list item in middle", () => {
            const editor = new MarkdownEditor("1. First item");
            editor.setCursor(9); // After "First"
            editor.insertNewline();
            
            expect(editor.getText()).toBe("1. First \n2. item");
        });

        test("Should exit list on empty item", () => {
            const editor = new MarkdownEditor("1. Item\n2. ");
            editor.setCursor(11); // End of empty item
            editor.insertNewline();
            
            expect(editor.getText()).toBe("1. Item\n2. \n\n");
        });

        test("Should handle nested lists", () => {
            const editor = new MarkdownEditor("  - Nested item");
            editor.setCursor(15);
            editor.insertNewline();
            
            expect(editor.getText()).toBe("  - Nested item\n  - ");
        });

        test("Should insert regular newline in non-list", () => {
            const editor = new MarkdownEditor("Regular text");
            editor.setCursor(7);
            editor.insertNewline();
            
            expect(editor.getText()).toBe("Regular\n text");
        });

        test("Should increment double-digit numbers", () => {
            const editor = new MarkdownEditor("10. Tenth item");
            editor.setCursor(14);
            editor.insertNewline();
            
            expect(editor.getText()).toBe("10. Tenth item\n11. ");
        });

        test("Should support undo for newline", () => {
            const editor = new MarkdownEditor("1. Item");
            editor.setCursor(7);
            editor.insertNewline();
            
            expect(editor.getText()).toBe("1. Item\n2. ");
            
            editor.undo();
            expect(editor.getText()).toBe("1. Item");
        });

        test("Should handle asterisk list marker", () => {
            const editor = new MarkdownEditor("* Item one");
            editor.setCursor(10);
            editor.insertNewline();
            
            expect(editor.getText()).toContain("* Item one\n- ");
        });
    });

    describe("HTML Rendering", () => {
        test("Should render markdown to HTML", () => {
            const editor = new MarkdownEditor("**bold** and *italic*");
            const html = editor.renderToHtml();
            
            expect(html).toContain("<strong>bold</strong>");
            expect(html).toContain("<em>italic</em>");
        });

        test("Should render headers to HTML", () => {
            const editor = new MarkdownEditor("# Header 1\n## Header 2");
            const html = editor.renderToHtml();
            
            expect(html).toContain("<h1>Header 1</h1>");
            expect(html).toContain("<h2>Header 2</h2>");
        });

        test("Should render lists to HTML", () => {
            const editor = new MarkdownEditor("- Item 1\n- Item 2");
            const html = editor.renderToHtml();
            
            expect(html).toContain("<ul>");
            expect(html).toContain("<li>Item 1</li>");
            expect(html).toContain("<li>Item 2</li>");
            expect(html).toContain("</ul>");
        });

        test("Should render ordered lists to HTML", () => {
            const editor = new MarkdownEditor("1. First\n2. Second");
            const html = editor.renderToHtml();
            
            expect(html).toContain("<ol>");
            expect(html).toContain("<li>First</li>");
            expect(html).toContain("<li>Second</li>");
            expect(html).toContain("</ol>");
        });

        test("Should render links to HTML", () => {
            const editor = new MarkdownEditor("[link](https://example.com)");
            const html = editor.renderToHtml();
            
            expect(html).toContain('<a href="https://example.com">link</a>');
        });

        test("Should render code blocks to HTML", () => {
            const editor = new MarkdownEditor("```\ncode here\n```");
            const html = editor.renderToHtml();
            
            expect(html).toContain("<pre><code>");
            expect(html).toContain("code here");
            expect(html).toContain("</code></pre>");
        });

        test("Should render inline code to HTML", () => {
            const editor = new MarkdownEditor("This is `inline code` here");
            const html = editor.renderToHtml();
            
            expect(html).toContain("<code>inline code</code>");
        });

        test("Should render strikethrough to HTML", () => {
            const editor = new MarkdownEditor("~~strikethrough~~");
            const html = editor.renderToHtml();
            
            expect(html).toContain("<del>strikethrough</del>");
        });

        test("Should handle complex markdown document", () => {
            const editor = new MarkdownEditor(
                "# Title\n\n" +
                "This is **bold** and *italic*.\n\n" +
                "- List item 1\n" +
                "- List item 2\n\n" +
                "[Link](https://example.com)"
            );
            const html = editor.renderToHtml();
            
            expect(html).toContain("<h1>Title</h1>");
            expect(html).toContain("<strong>bold</strong>");
            expect(html).toContain("<em>italic</em>");
            expect(html).toContain("<ul>");
            expect(html).toContain('<a href="https://example.com">Link</a>');
        });

        test("Should update HTML after operations", () => {
            const editor = new MarkdownEditor("text");
            editor.setSelection(0, 4);
            editor.applyOperation("bold");
            
            const html = editor.renderToHtml();
            expect(html).toContain("<strong>text</strong>");
        });
    });

    describe("Complex Workflows", () => {
        test("Should handle document creation workflow", () => {
            const editor = new MarkdownEditor("My Document");
            
            // Make title H1
            editor.setCursor(5);
            editor.applyOperation("header1");
            expect(editor.getText()).toContain("# My Document");
            
            // This would be adding content in a real scenario
            // For now just verify the header is there
            const spans = editor.render();
            const h1 = spans.find(s => s.style === "header1");
            expect(h1).toBeDefined();
        });

        test("Should handle list with formatting", () => {
            const editor = new MarkdownEditor("Task 1\nTask 2\nTask 3");
            
            // Create list
            editor.setSelection(0, editor.getText().length);
            editor.applyOperation("createUnorderedList");
            
            expect(editor.getText()).toContain("- Task 1");
            
            // Indent first task
            editor.setCursor(0);
            editor.applyOperation("indentList");
            
            expect(editor.getText()).toContain("  - Task 1");
        });

        test("Should handle combined formatting", () => {
            const editor = new MarkdownEditor("important urgent text");
            
            // Bold "important"
            editor.setSelection(0, 9);
            editor.applyOperation("bold");
            
            // Italic "urgent"
            const urgentPos = editor.getText().indexOf("urgent");
            editor.setSelection(urgentPos, urgentPos + 6);
            editor.applyOperation("italic");
            
            const text = editor.getText();
            expect(text).toContain("**important**");
            expect(text).toContain("*urgent*");
        });
    });
});

describe('MarkdownEditor - Text Editing Methods', () => {
    test('should set text and preserve cursor', () => {
        const editor = new MarkdownEditor('Hello');
        expect(editor.getCursor()).toBe(5);

        // Save state before changing text (setText doesn't auto-save)
        editor.saveUndoState();

        editor.setText('World');
        expect(editor.getText()).toBe('World');
        expect(editor.getCursor()).toBe(5); // Cursor at end

        // Should be undoable
        expect(editor.undo()).toBe(true);
        expect(editor.getText()).toBe('Hello');
    });

    test('should set text and adjust cursor if beyond length', () => {
        const editor = new MarkdownEditor('Hello world');
        editor.setCursor(11); // At end
        
        editor.setText('Hi'); // Much shorter
        expect(editor.getText()).toBe('Hi');
        expect(editor.getCursor()).toBe(2); // Adjusted to new end
    });

    test('should insert text at cursor', () => {
        const editor = new MarkdownEditor('Hello world');
        editor.setCursor(5);
        
        editor.insertText(' there');
        expect(editor.getText()).toBe('Hello there world');
        expect(editor.getCursor()).toBe(11);
    });

    test('should insert text replacing selection', () => {
        const editor = new MarkdownEditor('Hello world');
        editor.setSelection(0, 5);
        
        editor.insertText('Hi');
        expect(editor.getText()).toBe('Hi world');
        expect(editor.getCursor()).toBe(2);
    });

    test('should insert text with emoji', () => {
        const editor = new MarkdownEditor('Hello');
        editor.setCursor(5);
        
        editor.insertText(' 👋🌍');
        expect(editor.getText()).toBe('Hello 👋🌍');
    });

    test('should delete range', () => {
        const editor = new MarkdownEditor('Hello world');
        
        editor.deleteRange(5, 11);
        expect(editor.getText()).toBe('Hello');
        expect(editor.getCursor()).toBe(5);
        
        // Undo
        expect(editor.undo()).toBe(true);
        expect(editor.getText()).toBe('Hello world');
    });

    test('should delete selection', () => {
        const editor = new MarkdownEditor('Hello world');
        editor.setSelection(0, 5);
        
        const deleted = editor.deleteSelection();
        expect(deleted).toBe(true);
        expect(editor.getText()).toBe(' world');
        expect(editor.getCursor()).toBe(0);
    });

    test('should return false when deleting with no selection', () => {
        const editor = new MarkdownEditor('Hello');
        
        const deleted = editor.deleteSelection();
        expect(deleted).toBe(false);
        expect(editor.getText()).toBe('Hello'); // Unchanged
    });

    test('should replace range', () => {
        const editor = new MarkdownEditor('Hello world');
        
        editor.replaceRange(0, 5, 'Hi');
        expect(editor.getText()).toBe('Hi world');
        expect(editor.getCursor()).toBe(2);
        
        // Undo
        expect(editor.undo()).toBe(true);
        expect(editor.getText()).toBe('Hello world');
    });

    test('should support complete text editing workflow', () => {
        const editor = new MarkdownEditor('');
        
        // User types "Hello"
        editor.insertText('Hello');
        expect(editor.getText()).toBe('Hello');
        
        // User types " world"
        editor.insertText(' world');
        expect(editor.getText()).toBe('Hello world');
        
        // User selects "world" and applies bold
        editor.setSelection(6, 11);
        editor.applyOperation("bold");
        expect(editor.getText()).toBe('Hello **world**');
        
        // User continues typing (should be inside bold markers)
        editor.insertText('!');
        expect(editor.getText()).toBe('Hello **world!**');
        
        // Can undo all changes
        expect(editor.undo()).toBe(true); // Undo insert "!"
        expect(editor.undo()).toBe(true); // Undo bold
        expect(editor.undo()).toBe(true); // Undo " world"
        expect(editor.undo()).toBe(true); // Undo "Hello"
        expect(editor.getText()).toBe('');
    });

    test('should sync with native text input changes', () => {
        const editor = new MarkdownEditor('Hello');
        
        // Simulate native text input changing the text
        editor.setText('Hello world'); // Native input updated
        editor.setCursor(11); // Native input moved cursor to end
        
        expect(editor.getText()).toBe('Hello world');
        expect(editor.getCursor()).toBe(11);
        
        // Now user formats some text
        editor.setSelection(6, 11); // Select "world"
        editor.applyOperation("bold");
        expect(editor.getText()).toBe('Hello **world**');
        
        // Render to show formatting
        // Text is now "Hello **world**"
        // The renderer returns spans that include the markdown markers
        const spans = editor.render();
        const boldSpan = spans.find(s => s.style === "bold");
        expect(boldSpan).toBeDefined();
        expect(boldSpan!.start).toBe(6);  // Start of "**world**" including markers
        expect(boldSpan!.end).toBe(15);   // End of "**world**" including markers
    });
});

describe("Blockquote Operations", () => {
    test("Should apply blockquote to line", () => {
        const editor = new MarkdownEditor("This is a quote");
        editor.setSelection(0, 4);
        editor.applyOperation("blockquote");
        expect(editor.getText()).toBe("> This is a quote");
    });

    test("Should remove blockquote from line", () => {
        const editor = new MarkdownEditor("> This is a quote");
        editor.setCursor(5);
        editor.applyOperation("blockquote");
        expect(editor.getText()).toBe("This is a quote");
    });

    test("Should toggle blockquote", () => {
        const editor = new MarkdownEditor("Regular text");
        editor.setCursor(5);
        
        // Apply blockquote
        editor.applyOperation("blockquote");
        expect(editor.getText()).toBe("> Regular text");
        
        // Remove blockquote
        editor.applyOperation("blockquote");
        expect(editor.getText()).toBe("Regular text");
    });

    test("Should apply blockquote to second line", () => {
        const editor = new MarkdownEditor("First line\nSecond line");
        editor.setCursor(15); // In "Second"
        editor.applyOperation("blockquote");
        expect(editor.getText()).toBe("First line\n> Second line");
    });

    test("Should render blockquote spans", () => {
        const editor = new MarkdownEditor("> This is a quote");
        const spans = editor.render();
        
        const quoteSpans = spans.filter(s => s.style === "blockquote");
        expect(quoteSpans.length).toBeGreaterThan(0);
    });

    test("Should render blockquote in HTML", () => {
        const editor = new MarkdownEditor("> This is a quote");
        const html = editor.renderToHtml();
        
        expect(html).toContain("<blockquote>");
        expect(html).toContain("</blockquote>");
    });

    test("Should handle multiline blockquote in HTML", () => {
        const editor = new MarkdownEditor("> First line\n> Second line");
        const html = editor.renderToHtml();
        
        expect(html).toContain("<blockquote>");
        expect(html).toContain("First line");
        expect(html).toContain("Second line");
    });

    test("Should support undo/redo with blockquote", () => {
        const editor = new MarkdownEditor("Some text");
        editor.setCursor(4);

        // Apply blockquote
        editor.applyOperation("blockquote");
        expect(editor.getText()).toBe("> Some text");

        // Undo
        expect(editor.undo()).toBe(true);
        expect(editor.getText()).toBe("Some text");

        // Redo
        expect(editor.redo()).toBe(true);
        expect(editor.getText()).toBe("> Some text");
    });

    describe("Hybrid Mode - Markdown Markers", () => {
        test("Should render marker spans for bold", () => {
            const editor = new MarkdownEditor("**bold**");
            const spans = editor.render();

            // Should have bold span + 2 marker spans
            const boldSpan = spans.find(s => s.style === "bold");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(boldSpan).toBeDefined();
            expect(markerSpans.length).toBe(2);

            // Opening **
            expect(markerSpans[0].start).toBe(0);
            expect(markerSpans[0].end).toBe(2);

            // Closing **
            expect(markerSpans[1].start).toBe(6);
            expect(markerSpans[1].end).toBe(8);
        });

        test("Should render marker spans for italic", () => {
            const editor = new MarkdownEditor("*italic*");
            const spans = editor.render();

            const italicSpan = spans.find(s => s.style === "italic");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(italicSpan).toBeDefined();
            expect(markerSpans.length).toBe(2);

            // Opening *
            expect(markerSpans[0].start).toBe(0);
            expect(markerSpans[0].end).toBe(1);

            // Closing *
            expect(markerSpans[1].start).toBe(7);
            expect(markerSpans[1].end).toBe(8);
        });

        test("Should render marker spans for strikethrough", () => {
            const editor = new MarkdownEditor("~~strike~~");
            const spans = editor.render();

            const strikeSpan = spans.find(s => s.style === "strikethrough");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(strikeSpan).toBeDefined();
            expect(markerSpans.length).toBe(2);

            // Opening ~~
            expect(markerSpans[0].start).toBe(0);
            expect(markerSpans[0].end).toBe(2);

            // Closing ~~
            expect(markerSpans[1].start).toBe(8);
            expect(markerSpans[1].end).toBe(10);
        });

        test("Should render marker span for header", () => {
            const editor = new MarkdownEditor("# Header");
            const spans = editor.render();

            const headerSpan = spans.find(s => s.style === "header1");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(headerSpan).toBeDefined();
            expect(markerSpans.length).toBe(1);

            // # and space
            expect(markerSpans[0].start).toBe(0);
            expect(markerSpans[0].end).toBe(2);
        });

        test("Should render marker span for unordered list", () => {
            const editor = new MarkdownEditor("- Item");
            const spans = editor.render();

            const listSpan = spans.find(s => s.style === "unorderedListItem");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(listSpan).toBeDefined();
            expect(markerSpans.length).toBe(1);

            // - and space
            expect(markerSpans[0].start).toBe(0);
            expect(markerSpans[0].end).toBe(2);
        });

        test("Should render marker span for ordered list", () => {
            const editor = new MarkdownEditor("1. Item");
            const spans = editor.render();

            const listSpan = spans.find(s => s.style === "orderedListItem");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(listSpan).toBeDefined();
            expect(markerSpans.length).toBe(1);

            // 1. and space
            expect(markerSpans[0].start).toBe(0);
            expect(markerSpans[0].end).toBe(3);
        });

        test("Should render marker spans for inline code", () => {
            const editor = new MarkdownEditor("`code`");
            const spans = editor.render();

            const codeSpan = spans.find(s => s.style === "code");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(codeSpan).toBeDefined();
            expect(markerSpans.length).toBe(2);

            // Opening `
            expect(markerSpans[0].start).toBe(0);
            expect(markerSpans[0].end).toBe(1);

            // Closing `
            expect(markerSpans[1].start).toBe(5);
            expect(markerSpans[1].end).toBe(6);
        });

        test("Should render marker span for blockquote", () => {
            const editor = new MarkdownEditor("> Quote");
            const spans = editor.render();

            const quoteSpan = spans.find(s => s.style === "blockquote");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(quoteSpan).toBeDefined();
            expect(markerSpans.length).toBe(1);

            // > and space
            expect(markerSpans[0].start).toBe(0);
            expect(markerSpans[0].end).toBe(2);
        });

        test("Should render both content and marker spans for complex text", () => {
            const editor = new MarkdownEditor("This is **bold** and *italic* text");
            const spans = editor.render();

            const boldSpan = spans.find(s => s.style === "bold");
            const italicSpan = spans.find(s => s.style === "italic");
            const markerSpans = spans.filter(s => s.style === "markdownMarker");

            expect(boldSpan).toBeDefined();
            expect(italicSpan).toBeDefined();
            expect(markerSpans.length).toBe(4); // 2 for bold, 2 for italic
        });
    });
});
