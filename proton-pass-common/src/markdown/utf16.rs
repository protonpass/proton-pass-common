//! UTF-16 offset conversion utilities.
//!
//! Kotlin, Swift, and TypeScript/JavaScript use UTF-16 code units for string indexing.
//! Rust uses UTF-8 byte offsets internally. This module provides conversions between
//! UTF-8 byte offsets and UTF-16 code unit offsets.
//!
//! Key differences:
//! - ASCII characters: 1 byte in UTF-8, 1 code unit in UTF-16
//! - BMP characters (U+0080 to U+FFFF): 2-3 bytes in UTF-8, 1 code unit in UTF-16
//! - Supplementary characters (U+10000+): 4 bytes in UTF-8, 2 code units in UTF-16 (surrogate pair)

/// Convert UTF-8 byte offset to UTF-16 code unit offset
pub fn utf8_to_utf16_offset(text: &str, utf8_offset: usize) -> usize {
    if utf8_offset == 0 {
        return 0;
    }

    if utf8_offset >= text.len() {
        return text.encode_utf16().count();
    }

    // Count UTF-16 code units up to the UTF-8 byte offset
    text[..utf8_offset].encode_utf16().count()
}

/// Convert UTF-16 code unit offset to UTF-8 byte offset
#[allow(dead_code)]
pub fn utf16_to_utf8_offset(text: &str, utf16_offset: usize) -> usize {
    if utf16_offset == 0 {
        return 0;
    }

    let mut utf16_count = 0;
    let mut byte_offset = 0;

    for ch in text.chars() {
        let utf16_len = ch.len_utf16();

        if utf16_count + utf16_len > utf16_offset {
            // We've reached the target UTF-16 offset
            return byte_offset;
        }

        utf16_count += utf16_len;
        byte_offset += ch.len_utf8();
    }

    // If we've gone through the entire string, return the length
    text.len()
}

/// Convert UTF-16 code unit offset to UTF-8 byte offset only when the UTF-16
/// offset lands exactly on a Unicode scalar boundary.
pub fn strict_utf16_to_utf8_offset(text: &str, utf16_offset: usize) -> Option<usize> {
    let mut utf16_count = 0;
    let mut byte_offset = 0;

    if utf16_offset == 0 {
        return Some(0);
    }

    for ch in text.chars() {
        if utf16_count == utf16_offset {
            return Some(byte_offset);
        }

        let utf16_len = ch.len_utf16();
        if utf16_count < utf16_offset && utf16_offset < utf16_count + utf16_len {
            return None;
        }

        utf16_count += utf16_len;
        byte_offset += ch.len_utf8();
    }

    if utf16_count == utf16_offset {
        Some(text.len())
    } else {
        None
    }
}

/// Validate that a UTF-16 offset is at a valid character boundary
/// Returns true if the offset is valid, false otherwise
#[allow(dead_code)]
pub fn is_valid_utf16_offset(text: &str, utf16_offset: usize) -> bool {
    strict_utf16_to_utf8_offset(text, utf16_offset).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_conversion() {
        let text = "hello world";

        // ASCII: 1 byte = 1 code unit
        assert_eq!(utf8_to_utf16_offset(text, 0), 0);
        assert_eq!(utf8_to_utf16_offset(text, 5), 5);
        assert_eq!(utf8_to_utf16_offset(text, 11), 11);

        assert_eq!(utf16_to_utf8_offset(text, 0), 0);
        assert_eq!(utf16_to_utf8_offset(text, 5), 5);
        assert_eq!(utf16_to_utf8_offset(text, 11), 11);
    }

    #[test]
    fn test_emoji_conversion() {
        let text = "hello 😀 world";
        // "hello " = 6 bytes, 6 code units
        // 😀 = 4 bytes (U+1F600), 2 code units (surrogate pair)
        // " world" = 6 bytes, 6 code units

        // Before emoji
        assert_eq!(utf8_to_utf16_offset(text, 6), 6);
        assert_eq!(utf16_to_utf8_offset(text, 6), 6);

        // After emoji
        assert_eq!(utf8_to_utf16_offset(text, 10), 8); // 6 + 4 bytes -> 6 + 2 code units
        assert_eq!(utf16_to_utf8_offset(text, 8), 10);

        // End of string
        assert_eq!(utf8_to_utf16_offset(text, 16), 14);
        assert_eq!(utf16_to_utf8_offset(text, 14), 16);
    }

    #[test]
    fn test_strict_conversion_rejects_middle_of_surrogate_pair() {
        let text = "a😀b";

        assert_eq!(strict_utf16_to_utf8_offset(text, 1), Some(1));
        assert_eq!(strict_utf16_to_utf8_offset(text, 2), None);
        assert_eq!(strict_utf16_to_utf8_offset(text, 3), Some(5));
    }

    #[test]
    fn test_multibyte_characters() {
        let text = "Héllo wörld"; // é = 2 bytes, ö = 2 bytes

        // Before é (H)
        assert_eq!(utf8_to_utf16_offset(text, 1), 1);
        assert_eq!(utf16_to_utf8_offset(text, 1), 1);

        // After é
        assert_eq!(utf8_to_utf16_offset(text, 3), 2); // H + é (2 bytes) = position 2 in UTF-16
        assert_eq!(utf16_to_utf8_offset(text, 2), 3);

        // After ö
        assert_eq!(utf8_to_utf16_offset(text, 10), 8); // "Héllo wö" = 10 bytes, 8 code units
        assert_eq!(utf16_to_utf8_offset(text, 8), 10);
    }

    #[test]
    fn test_mixed_content() {
        let text = "Test 你好 😀!";
        // "Test " = 5 bytes, 5 code units
        // 你 = 3 bytes (U+4F60), 1 code unit
        // 好 = 3 bytes (U+597D), 1 code unit
        // " " = 1 byte, 1 code unit
        // 😀 = 4 bytes (U+1F600), 2 code units
        // "!" = 1 byte, 1 code unit

        assert_eq!(utf8_to_utf16_offset(text, 5), 5); // Before 你
        assert_eq!(utf8_to_utf16_offset(text, 8), 6); // After 你
        assert_eq!(utf8_to_utf16_offset(text, 11), 7); // After 好
        assert_eq!(utf8_to_utf16_offset(text, 12), 8); // After space
        assert_eq!(utf8_to_utf16_offset(text, 16), 10); // After 😀
        assert_eq!(utf8_to_utf16_offset(text, 17), 11); // End

        assert_eq!(utf16_to_utf8_offset(text, 5), 5);
        assert_eq!(utf16_to_utf8_offset(text, 6), 8);
        assert_eq!(utf16_to_utf8_offset(text, 7), 11);
        assert_eq!(utf16_to_utf8_offset(text, 8), 12);
        assert_eq!(utf16_to_utf8_offset(text, 10), 16);
        assert_eq!(utf16_to_utf8_offset(text, 11), 17);
    }

    #[test]
    fn test_round_trip_conversion() {
        let texts = vec![
            "simple ascii",
            "Héllo wörld",
            "你好世界",
            "Test 😀 emoji 🎉 here",
            "Mixed: ASCII, 中文, and 🚀 symbols!",
        ];

        for text in texts {
            // Test round trips for each character boundary
            let mut utf8_offset = 0;
            for ch in text.chars() {
                // Test at the start of this character
                let utf16_offset = utf8_to_utf16_offset(text, utf8_offset);
                let back_to_utf8 = utf16_to_utf8_offset(text, utf16_offset);

                assert_eq!(
                    utf8_offset, back_to_utf8,
                    "Round trip failed for text '{}' at UTF-8 offset {} (UTF-16: {})",
                    text, utf8_offset, utf16_offset
                );

                utf8_offset += ch.len_utf8();
            }

            // Test at end of string
            let utf16_offset = utf8_to_utf16_offset(text, text.len());
            let back_to_utf8 = utf16_to_utf8_offset(text, utf16_offset);
            assert_eq!(text.len(), back_to_utf8, "Round trip failed at end of text '{}'", text);
        }
    }

    #[test]
    fn test_boundary_cases() {
        let text = "test";

        // Zero offset
        assert_eq!(utf8_to_utf16_offset(text, 0), 0);
        assert_eq!(utf16_to_utf8_offset(text, 0), 0);

        // End of string
        assert_eq!(utf8_to_utf16_offset(text, 4), 4);
        assert_eq!(utf16_to_utf8_offset(text, 4), 4);

        // Beyond end
        assert_eq!(utf8_to_utf16_offset(text, 100), 4);
        assert_eq!(utf16_to_utf8_offset(text, 100), 4);
    }

    #[test]
    fn test_empty_string() {
        let text = "";
        assert_eq!(utf8_to_utf16_offset(text, 0), 0);
        assert_eq!(utf16_to_utf8_offset(text, 0), 0);
    }

    #[test]
    fn test_validation() {
        let text = "hello 😀 world";

        // Valid offsets
        assert!(is_valid_utf16_offset(text, 0));
        assert!(is_valid_utf16_offset(text, 6)); // Before emoji
        assert!(is_valid_utf16_offset(text, 8)); // After emoji (2 code units)
        assert!(is_valid_utf16_offset(text, 14)); // End

        // All character boundaries should be valid
        for (byte_offset, _) in text.char_indices() {
            let utf16_offset = utf8_to_utf16_offset(text, byte_offset);
            assert!(
                is_valid_utf16_offset(text, utf16_offset),
                "Character boundary at byte {} (UTF-16 offset {}) should be valid",
                byte_offset,
                utf16_offset
            );
        }
    }

    #[test]
    fn test_surrogate_pairs() {
        // Test various emoji that use surrogate pairs in UTF-16
        let emojis = vec![
            ("😀", 4, 2),   // U+1F600
            ("🎉", 4, 2),   // U+1F389
            ("🚀", 4, 2),   // U+1F680
            ("👨‍👩‍👧‍👦", 25, 11), // Family emoji with ZWJ sequences
        ];

        for (emoji, utf8_len, utf16_len) in emojis {
            assert_eq!(
                utf8_to_utf16_offset(emoji, utf8_len),
                utf16_len,
                "Failed for emoji: {}",
                emoji
            );
            assert_eq!(
                utf16_to_utf8_offset(emoji, utf16_len),
                utf8_len,
                "Failed for emoji: {}",
                emoji
            );
        }
    }
}
