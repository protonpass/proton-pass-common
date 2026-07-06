import { describe, expect, test } from "bun:test";

// Import from the worker pkg which has resize-image feature enabled
import { convert_image_to_256_png } from "./pkg/worker";

const TEST_IMAGES_DIR = new URL("./test_images", import.meta.url).pathname;

async function readTestImage(filename: string): Promise<Uint8Array> {
    const filePath = `${TEST_IMAGES_DIR}/${filename}`;
    const buffer = await Bun.file(filePath).arrayBuffer();
    return new Uint8Array(buffer);
}

describe("ProtonPassWeb Image Conversion", () => {
    test("Can convert JPEG to PNG", async () => {
        const jpegBytes = await readTestImage("sample.jpg");
        
        const result = convert_image_to_256_png(jpegBytes);
        
        expect(result).toBeDefined();
        expect(result.length).toBeGreaterThan(0);
        
        // Verify it's a valid PNG by checking the magic number
        expect(result[0]).toBe(0x89);
        expect(result[1]).toBe(0x50); // 'P'
        expect(result[2]).toBe(0x4E); // 'N'
        expect(result[3]).toBe(0x47); // 'G'
    });

    test("Can convert PNG to PNG", async () => {
        const pngBytes = await readTestImage("sample.png");
        
        const result = convert_image_to_256_png(pngBytes);
        
        expect(result).toBeDefined();
        expect(result.length).toBeGreaterThan(0);
        
        // Verify it's a valid PNG
        expect(result[0]).toBe(0x89);
        expect(result[1]).toBe(0x50);
        expect(result[2]).toBe(0x4E);
        expect(result[3]).toBe(0x47);
    });

    test("Unsupported format throws error", async () => {
        // Try with a text file which should fail
        const txtBytes = await readTestImage("sample.txt");
        
        expect(() => {
            convert_image_to_256_png(txtBytes);
        }).toThrow();
    });

    test("Output is always PNG format", async () => {
        const jpegBytes = await readTestImage("sample.jpg");
        
        const result = convert_image_to_256_png(jpegBytes);
        
        // PNG signature: 89 50 4E 47 0D 0A 1A 0A
        expect(result[0]).toBe(0x89);
        expect(result[1]).toBe(0x50); // 'P'
        expect(result[2]).toBe(0x4E); // 'N'
        expect(result[3]).toBe(0x47); // 'G'
    });
});
