import { describe, expect, test } from "bun:test";

import { parseMarkdownDocument } from "./pkg/ui";

type ChildNode = TestElement | TestText | TestFragment;

class TestText {
    readonly nodeType = "text";

    constructor(public textContent: string) {}
}

class TestFragment {
    readonly nodeType = "fragment";
    children: ChildNode[] = [];

    appendChild(child: ChildNode) {
        this.children.push(child);
        return child;
    }
}

class TestElement {
    readonly nodeType = "element";
    children: ChildNode[] = [];
    className = "";
    title = "";
    href = "";
    rel = "";
    start = 0;
    dataset: Record<string, string> = {};
    private textOverride: string | undefined;

    constructor(public tagName: string) {}

    appendChild(child: ChildNode) {
        this.children.push(child);
        this.textOverride = undefined;
        return child;
    }

    replaceChildren(...children: ChildNode[]) {
        this.children = children.flatMap(child => child instanceof TestFragment ? child.children : [child]);
        this.textOverride = undefined;
    }

    get textContent(): string {
        if (this.textOverride !== undefined) {
            return this.textOverride;
        }
        return this.children.map(child => child.textContent).join("");
    }

    set textContent(value: string) {
        this.textOverride = value;
        this.children = [];
    }

    querySelector(tagName: string): TestElement | undefined {
        return this.queryAll(tagName)[0];
    }

    queryAll(tagName: string): TestElement[] {
        const matches: TestElement[] = [];
        this.walk(child => {
            if (child instanceof TestElement && child.tagName === tagName) {
                matches.push(child);
            }
        });
        return matches;
    }

    queryByClass(className: string): TestElement | undefined {
        let match: TestElement | undefined;
        this.walk(child => {
            if (
                !match &&
                child instanceof TestElement &&
                child.className.split(/\s+/).includes(className)
            ) {
                match = child;
            }
        });
        return match;
    }

    private walk(visitor: (child: ChildNode) => void) {
        for (const child of this.children) {
            visitor(child);
            if (child instanceof TestElement) {
                child.walk(visitor);
            } else if (child instanceof TestFragment) {
                child.children.forEach(visitor);
            }
        }
    }
}

class TestDocument {
    createElement(tagName: string) {
        return new TestElement(tagName);
    }

    createTextNode(text: string) {
        return new TestText(text);
    }

    createDocumentFragment() {
        return new TestFragment();
    }
}

async function render(markdown: string): Promise<TestElement> {
    globalThis.document = new TestDocument() as unknown as Document;
    globalThis.window = { addEventListener: () => {} } as unknown as Window & typeof globalThis;
    const { renderMarkdownDocument } = await import("./test-markdown-website/script.js");
    const container = new TestElement("div");

    renderMarkdownDocument(container, parseMarkdownDocument(markdown));

    return container;
}

describe("Markdown website DOM renderer", () => {
    test("renders unsafe links as non-clickable spans", async () => {
        const container = await render("[unsafe](javascript:alert(1))");

        expect(container.querySelector("a")).toBeUndefined();
        const unsafeLink = container.queryByClass("unsafe-link");
        expect(unsafeLink).toBeDefined();
        expect(unsafeLink?.textContent).toBe("unsafe");
        expect(unsafeLink?.title).toBe("Unsafe link: unsupportedScheme");
    });

    test("renders safe links as anchors with rel protection", async () => {
        const container = await render("[safe](HTTPS://Example.COM/Path)");
        const anchor = container.querySelector("a");

        expect(anchor?.textContent).toBe("safe");
        expect(anchor?.href).toBe("HTTPS://Example.COM/Path");
        expect(anchor?.rel).toBe("noopener noreferrer");
    });

    test("renders raw HTML as literal text", async () => {
        const container = await render("Click <kbd>Enter</kbd> <script>alert(1)</script>");

        expect(container.textContent).toContain("<kbd>Enter</kbd>");
        expect(container.textContent).toContain("<script>alert(1)</script>");
        expect(container.querySelector("kbd")).toBeUndefined();
        expect(container.querySelector("script")).toBeUndefined();
    });

    test("preserves code block whitespace and language", async () => {
        const container = await render("```rust\nfn main() {\n    println!(\"hi\");\n}\n```");
        const pre = container.querySelector("pre");
        const code = container.querySelector("code");

        expect(pre).toBeDefined();
        expect(code?.dataset.language).toBe("rust");
        expect(code?.textContent).toBe("fn main() {\n    println!(\"hi\");\n}\n");
    });
});
