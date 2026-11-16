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
