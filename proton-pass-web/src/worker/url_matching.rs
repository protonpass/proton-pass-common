use proton_pass_common::url_matching::{self, UrlMatchResult, UrlMatchingCandidate};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

#[derive(Tsify, Deserialize, Serialize)]
pub struct WasmUrlMatchingCandidates(pub Vec<UrlMatchingCandidate>);

#[derive(Tsify, Deserialize, Serialize)]
pub struct WasmUrlMatchResults(pub Vec<UrlMatchResult>);

#[wasm_bindgen]
pub fn match_urls(
    url: String,
    candidates: Ts<WasmUrlMatchingCandidates>,
    private_domains: Vec<String>,
) -> Result<Ts<WasmUrlMatchResults>, JsError> {
    let candidates = candidates.to_rust()?.0;
    Ok(WasmUrlMatchResults(url_matching::match_urls(&url, candidates, private_domains)).into_ts()?)
}

#[wasm_bindgen]
pub fn url_matches_pattern(pattern: String, url: String) -> Result<bool, JsError> {
    Ok(url_matching::url_matches_pattern(&pattern, &url)?)
}

#[wasm_bindgen]
pub fn url_matches_regex(regex: String, url: String) -> Result<bool, JsError> {
    Ok(url_matching::url_matches_regex(&regex, &url)?)
}
