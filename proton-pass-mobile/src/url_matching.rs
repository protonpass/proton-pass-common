use proton_pass_common::url_matching::{
    UrlMatchResult, UrlMatchingCandidate, UrlMatchingError, match_urls, url_matches_pattern, url_matches_regex,
};

#[derive(uniffi::Object)]
pub struct UrlMatcher;

#[uniffi::export]
impl UrlMatcher {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn match_urls(
        &self,
        url: String,
        candidates: Vec<UrlMatchingCandidate>,
        private_domains: Option<Vec<String>>,
    ) -> Vec<UrlMatchResult> {
        match_urls(&url, candidates, private_domains.unwrap_or_default())
    }

    pub fn url_matches_pattern(&self, pattern: String, url: String) -> Result<bool, UrlMatchingError> {
        url_matches_pattern(&pattern, &url)
    }

    pub fn url_matches_regex(&self, regex: String, url: String) -> Result<bool, UrlMatchingError> {
        url_matches_regex(&regex, &url)
    }
}
