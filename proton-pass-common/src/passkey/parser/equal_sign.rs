use super::PasskeySanitizer;

pub struct EqualSignSanitizer;

impl PasskeySanitizer for EqualSignSanitizer {
    fn should_sanitize(&self, _: Option<&str>, request: &str) -> bool {
        request.contains("\\u003d")
    }

    fn sanitize(&self, request: &str) -> String {
        request.replace("\\u003d", "=")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn performs_replace() {
        let input = "ABC\\u003dABC";
        let expected = "ABC=ABC";
        assert_ne!(input, expected);

        let res = EqualSignSanitizer.sanitize(input);
        assert_eq!("ABC=ABC", res);
    }
}
