import { describe, expect, test } from "bun:test";

// Import from the worker pkg which has resize-image feature enabled
import { convert_image_to_256_webp } from "./pkg/worker";

const TEST_IMAGES_DIR = new URL("./test_images", import.meta.url).pathname;

async function readTestImage(filename: string): Promise<Uint8Array> {
    const filePath = `${TEST_IMAGES_DIR}/${filename}`;
    const buffer = await Bun.file(filePath).arrayBuffer();
    return new Uint8Array(buffer);
}

describe("ProtonPassWeb Image Conversion", () => {
    test("Can convert JPEG to WebP", async () => {
        const jpegBytes = await readTestImage("sample.jpg");
        
        const result = convert_image_to_256_webp(jpegBytes);
        
        expect(result).toBeDefined();
        expect(result.length).toBeGreaterThan(0);
        
        // Verify it's a valid WebP by checking the RIFF header
        expect(result[0]).toBe(0x52); // 'R'
        expect(result[1]).toBe(0x49); // 'I'
        expect(result[2]).toBe(0x46); // 'F'
        expect(result[3]).toBe(0x46); // 'F'
    });

    test("Can convert PNG to WebP", async () => {
        const pngBytes = await readTestImage("sample.png");
        
        const result = convert_image_to_256_webp(pngBytes);
        
        expect(result).toBeDefined();
        expect(result.length).toBeGreaterThan(0);
        
        // Verify it's a valid WebP
        expect(result[0]).toBe(0x52); // 'R'
        expect(result[1]).toBe(0x49); // 'I'
        expect(result[2]).toBe(0x46); // 'F'
        expect(result[3]).toBe(0x46); // 'F'
    });

    test("Can convert WebP to WebP", async () => {
        const webpBytes = await readTestImage("sample.webp");
        
        const result = convert_image_to_256_webp(webpBytes);
        
        expect(result).toBeDefined();
        expect(result.length).toBeGreaterThan(0);
        
        // Verify it's a valid WebP
        expect(result[0]).toBe(0x52); // 'R'
        expect(result[1]).toBe(0x49); // 'I'
        expect(result[2]).toBe(0x46); // 'F'
        expect(result[3]).toBe(0x46); // 'F'
    });

    test("Unsupported format throws error", async () => {
        // Try with a text file which should fail
        const txtBytes = await readTestImage("sample.txt");
        
        let error;
        try {
            convert_image_to_256_webp(txtBytes);
        } catch (e) {
            error = e;
        }
        
        expect(error).toBeDefined();
        expect(error.type).toBe("UnsupportedInputFormat")
    });
});
