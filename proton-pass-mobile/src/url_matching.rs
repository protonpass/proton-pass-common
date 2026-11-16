use proton_pass_common::url_matching::{UrlMatchResult, UrlMatchingCandidate, match_urls};

#[derive(uniffi::Object)]
pub struct UrlMatcher;

#[uniffi::export]
impl UrlMatcher {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn match_urls(&self, url: String, candidates: Vec<UrlMatchingCandidate>) -> Vec<UrlMatchResult> {
        match_urls(&url, candidates, vec![])
    }
}
