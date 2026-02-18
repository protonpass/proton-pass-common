use rand::Rng;

#[cfg(feature = "wasm")]
use proton_pass_derive::ffi_type;

pub const NUMBERS: &str = "0123456789";
pub const SYMBOLS: &str = "!@#$%^&*";

#[cfg_attr(feature = "wasm", ffi_type(web_name = "WasmWordSeparator"))]
#[derive(Clone, Debug)]
pub enum WordSeparator {
    Hyphens,
    Spaces,
    Periods,
    Commas,
    Underscores,
    Numbers,
    NumbersAndSymbols,
}

impl WordSeparator {
    pub fn all() -> Vec<WordSeparator> {
        vec![
            WordSeparator::Hyphens,
            WordSeparator::Spaces,
            WordSeparator::Periods,
            WordSeparator::Commas,
            WordSeparator::Underscores,
            WordSeparator::Numbers,
            WordSeparator::NumbersAndSymbols,
        ]
    }
}

/// Get the separator string based on the WordSeparator variant
pub fn get_separator<R: Rng>(rng: &mut R, separator: &WordSeparator) -> String {
    match separator {
        WordSeparator::Numbers => {
            let num = rng.random_range(0..=9);
            num.to_string()
        }
        WordSeparator::NumbersAndSymbols => {
            let chars: Vec<char> = format!("{}{}", NUMBERS, SYMBOLS).chars().collect();
            let idx = rng.random_range(0..chars.len());
            chars[idx].to_string()
        }
        WordSeparator::Hyphens => "-".to_string(),
        WordSeparator::Spaces => " ".to_string(),
        WordSeparator::Periods => ".".to_string(),
        WordSeparator::Commas => ",".to_string(),
        WordSeparator::Underscores => "_".to_string(),
    }
}

pub fn capitalize(word: String) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

pub fn to_leetspeak(word: String) -> String {
    word.chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a' => '4',
            'b' => '8',
            'e' => '3',
            'g' => '6',
            'i' => '1',
            'o' => '0',
            's' => '5',
            't' => '7',
            'z' => '2',
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::StdRng;
    use rand::SeedableRng;

    fn seeded_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn test_get_separator_static() {
        let mut rng = seeded_rng();
        let cases = [
            (WordSeparator::Hyphens, "-"),
            (WordSeparator::Spaces, " "),
            (WordSeparator::Periods, "."),
            (WordSeparator::Commas, ","),
            (WordSeparator::Underscores, "_"),
        ];

        for (separator, expected) in cases {
            assert_eq!(get_separator(&mut rng, &separator), expected);
        }
    }

    #[test]
    fn test_get_separator_random() {
        let mut rng = seeded_rng();

        // Test Numbers variant
        for _ in 0..20 {
            let result = get_separator(&mut rng, &WordSeparator::Numbers);
            assert!(NUMBERS.contains(&result));
        }

        // Test NumbersAndSymbols variant
        let valid_chars = format!("{}{}", NUMBERS, SYMBOLS);
        for _ in 0..20 {
            let result = get_separator(&mut rng, &WordSeparator::NumbersAndSymbols);
            assert!(valid_chars.contains(&result));
        }
    }

    #[test]
    fn test_capitalize() {
        let cases = [
            ("", ""),
            ("a", "A"),
            ("A", "A"),
            ("hello", "Hello"),
            ("Hello", "Hello"),
            ("HELLO", "HELLO"),
            ("123abc", "123abc"),
            ("!hello", "!hello"),
            ("café", "Café"),
            ("hello world", "Hello world"),
        ];

        for (input, expected) in cases {
            assert_eq!(capitalize(input.to_string()), expected);
        }
    }

    #[test]
    fn test_to_leetspeak() {
        let cases = [
            ("", ""),
            ("xyz", "xy2"),
            ("hello", "h3ll0"),
            ("test", "7357"),
            ("awesome", "4w350m3"),
            ("HELLO", "H3LL0"),
            ("HeLLo", "H3LL0"),
            ("hello world", "h3ll0 w0rld"),
            ("hello123", "h3ll0123"),
            ("abegiostaz", "4836105742"),
        ];

        for (input, expected) in cases {
            assert_eq!(to_leetspeak(input.to_string()), expected);
        }
    }

    #[test]
    fn test_word_separator_all() {
        let all = WordSeparator::all();
        assert_eq!(all.len(), 7);
        assert!(all.contains(&WordSeparator::Hyphens));
        assert!(all.contains(&WordSeparator::Numbers));
        assert!(all.contains(&WordSeparator::NumbersAndSymbols));
    }
}
