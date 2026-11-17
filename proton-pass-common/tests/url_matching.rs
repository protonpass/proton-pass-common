#![cfg(feature = "url-matching")]

use proton_pass_common::url_matching::{
    MAX_SCORE, UrlMatchResult, UrlMatchingCandidate, UrlMatchingError, match_urls, url_matches_pattern,
    url_matches_regex,
};
use proton_pass_types::{AutofillUrl, AutofillUrlMode};

use AutofillUrlMode::*;

fn candidate(id: &str, urls: &[(&str, AutofillUrlMode)]) -> UrlMatchingCandidate {
    UrlMatchingCandidate {
        item_id: id.to_string(),
        share_id: "share".to_string(),
        url_mode: urls
            .iter()
            .map(|(url, mode)| AutofillUrl {
                url: url.to_string(),
                mode: *mode,
            })
            .collect(),
    }
}

/// Score of a single item on `page`, `None` when it doesn't match.
fn score(page: &str, urls: &[(&str, AutofillUrlMode)]) -> Option<u32> {
    score_with_private_domains(page, urls, &[])
}

fn score_with_private_domains(page: &str, urls: &[(&str, AutofillUrlMode)], private_domains: &[&str]) -> Option<u32> {
    let private_domains = private_domains.iter().map(|s| s.to_string()).collect();
    match_urls(page, vec![candidate("item", urls)], private_domains)
        .first()
        .map(|r| r.score)
}

fn default(page: &str, urls: &[&str]) -> Option<u32> {
    let urls: Vec<_> = urls.iter().map(|u| (*u, Default)).collect();
    score(page, &urls)
}

#[test]
fn default_mode_no_match() {
    assert_eq!(default("pm.me", &["https://proton.ch"]), None);
    assert_eq!(default("proton.ch", &["https://pproton.ch"]), None);
    assert_eq!(default("proton.ch", &["https://p.pproton.ch"]), None);
    assert_eq!(default("http://proton.ch", &["https://proton.ch"]), None);
    assert_eq!(default("http://proton.ch", &["ftp://proton.ch"]), None);
    assert_eq!(default("http://proton.ch", &["ftp://sub.proton.ch"]), None);
    assert_eq!(default("https://proton.ch", &["ftp://proton.ch"]), None);
    assert_eq!(default("ftp://proton.ch", &["https://proton.ch"]), None);
    assert_eq!(default("https://proton.ch:3001", &["https://proton.ch:3002"]), None);
    assert_eq!(default("https://example.com:3000/", &["example.com:4000"]), None);
    assert_eq!(default("https://[::1]/", &["https://[::2]/"]), None);
    assert_eq!(
        score_with_private_domains("b.c.me", &[("https://a.b.c.me", Default)], &["b.c.me"]),
        None
    );
    assert_eq!(
        score_with_private_domains(
            "https://b.example.com",
            &[("https://a.example.com", Default)],
            &["example.com"]
        ),
        None
    );
    for invalid in ["https::/proton.ch", ",,,,/proton.ch", " ", ""] {
        assert_eq!(default("proton.ch", &[invalid]), None, "{invalid}");
    }
    for invalid_page in ["", "http::://invalid.com", " "] {
        assert_eq!(default(invalid_page, &["https://proton.me"]), None, "{invalid_page}");
    }
}

#[test]
fn default_mode_sub_and_top_matches() {
    assert_eq!(default("pm.me", &["https://subdomain.pm.me"]), Some(MAX_SCORE - 1));
    assert_eq!(
        default("subdomain.pm.me", &["http://nested.subdomain.pm.me"]),
        Some(MAX_SCORE - 1)
    );
    assert_eq!(
        default("http://proton.ch", &["http://sub.proton.ch"]),
        Some(MAX_SCORE - 1)
    );
    assert_eq!(
        default("http://proton.ch:3001", &["http://sub.proton.ch:3001"]),
        Some(MAX_SCORE - 1)
    );
    assert_eq!(
        default("proton.ch", &["http://sub.proton.ch:3001"]),
        Some(MAX_SCORE - 1)
    );
    assert_eq!(default("b.c.me", &["https://a.b.c.me"]), Some(MAX_SCORE - 1));
    assert_eq!(
        default("example.com", &["https://sub.example.com/path?query=param"]),
        Some(MAX_SCORE - 1)
    );
    assert_eq!(default("a.b.pm.me", &["https://pm.me"]), Some(MAX_SCORE - 2));
    assert_eq!(default("a.b.c.pm.me", &["https://pm.me"]), Some(MAX_SCORE - 3));
    assert_eq!(
        score_with_private_domains(
            "https://login.a.example.com",
            &[("https://a.example.com", Default)],
            &["example.com"]
        ),
        Some(MAX_SCORE - 1)
    );
    // sibling
    assert_eq!(
        default("b.example.com", &["https://a.example.com"]),
        Some(MAX_SCORE - 1)
    );
    assert_eq!(
        default("b.example.com", &["https://a.b.example.com"]),
        Some(MAX_SCORE - 1)
    );
}

#[test]
fn default_mode_exact_matches() {
    assert_eq!(default("pm.me", &["https://pm.me"]), Some(MAX_SCORE));
    assert_eq!(default("proton.ch", &["nomatch", "https://proton.ch"]), Some(MAX_SCORE));
    assert_eq!(default("ftp://proton.ch", &["ftp://proton.ch"]), Some(MAX_SCORE));
    assert_eq!(
        default("http://proton.ch:3001", &["http://proton.ch:3001"]),
        Some(MAX_SCORE)
    );
    assert_eq!(default("proton.ch", &["http://proton.ch:3001"]), Some(MAX_SCORE));
    assert_eq!(
        default("https://localhost:3000/login", &["localhost:3000"]),
        Some(MAX_SCORE)
    );
    assert_eq!(
        default("https://example.com:3000/", &["example.com:3000"]),
        Some(MAX_SCORE)
    );
    assert_eq!(default("https://[::1]/", &["https://[::1]/"]), Some(MAX_SCORE));
    assert_eq!(default("192.168.1.1", &["http://192.168.1.1"]), Some(MAX_SCORE));
    assert_eq!(default("192.168.1.1", &["https://192.168.1.1/path"]), Some(MAX_SCORE));
    assert_eq!(
        default("example.com", &["https://example.com/path?query=param"]),
        Some(MAX_SCORE)
    );
    assert_eq!(default("a.b.c.me", &["https://a.b.c.me"]), Some(MAX_SCORE));
    assert_eq!(
        default("a.example.com", &["https://example.com", "https://a.example.com"]),
        Some(MAX_SCORE)
    );
    assert_eq!(
        default("https://www.proton.me", &["https://proton.me"]),
        Some(MAX_SCORE)
    );
}

#[test]
fn default_mode_bare_public_suffix_never_matches() {
    // A saved public suffix must not match its children.
    assert_eq!(default("https://evil.github.io", &["https://github.io"]), None);
    assert_eq!(default("https://example.com", &["https://com"]), None);
    assert_eq!(default("https://a.github.io", &["https://b.github.io"]), None);
}

#[test]
fn http_item_matches_https_page_but_not_the_reverse() {
    for mode in [Default, Exact] {
        assert_eq!(
            score("https://proton.me", &[("http://proton.me", mode)]),
            Some(MAX_SCORE),
            "{mode:?}"
        );
        assert_eq!(
            score("http://proton.me", &[("https://proton.me", mode)]),
            None,
            "{mode:?}"
        );
    }
}

#[test]
fn exact_mode() {
    assert_eq!(score("pm.me", &[("https://proton.ch", Exact)]), None);
    assert_eq!(score("b.example.com", &[("https://example.com", Exact)]), None);
    assert_eq!(
        score("a.example.com", &[("https://a.example.com", Exact)]),
        Some(MAX_SCORE)
    );
    assert_eq!(
        score_with_private_domains(
            "https://www.a.example.com",
            &[("https://www.a.example.com", Exact)],
            &["example.com"]
        ),
        Some(MAX_SCORE)
    );
}

#[test]
fn never_mode() {
    assert_eq!(score("pm.me", &[("https://proton.ch", Never)]), None);
    assert_eq!(score("example.com", &[("https://example.com", Never)]), None);
    let blocked = [("https://example.com", Default), ("https://example.com", Never)];
    assert_eq!(score("example.com", &blocked), None);
    assert_eq!(score("login.example.com", &blocked), Some(MAX_SCORE - 1));
    let other = [("https://example.com", Default), ("https://other.com", Never)];
    assert_eq!(score("example.com", &other), Some(MAX_SCORE));
    let ancestor = [("https://example.com", Default), ("https://never.example.com", Never)];
    assert_eq!(score("login.example.com", &ancestor), Some(MAX_SCORE - 1));

    let logout = [
        ("https://example.com", ExactPath),
        ("https://example.com/logout", Never),
    ];
    assert_eq!(score("https://example.com", &logout), Some(MAX_SCORE));
    assert_eq!(score("https://example.com/logout", &logout), None);

    let sso = [
        ("https://sso.megacorp.com/login", ExactPath),
        ("https://sso.megacorp.com/logout", Never),
    ];
    assert_eq!(score("https://sso.megacorp.com/login", &sso), Some(MAX_SCORE));
    assert_eq!(score("https://sso.megacorp.com/logout", &sso), None);

    let query = [("https://example.com", Default), ("https://example.com/logout", Never)];
    assert_eq!(score("https://example.com/logout?ref=abc#top", &query), None);
}

#[test]
fn start_with_mode() {
    let s = |page, url| score(page, &[(url, StartWith)]);
    assert_eq!(
        s("https://proton.me/drive?param=value#hash", "https://proton.me/pass"),
        None
    );
    assert_eq!(s("https://proton.me.evil.com/pass", "https://proton.me"), None);
    assert_eq!(
        s(
            "https://proton.me/pass/something?param=value#hash",
            "https://proton.me/pass"
        ),
        Some(MAX_SCORE)
    );
    assert_eq!(s("https://proton.me/pass", "https://proton.me/pass"), Some(MAX_SCORE));
    assert_eq!(s("https://proton.me", "https://proton.me"), Some(MAX_SCORE));
    // Custom schemes keep the host
    assert_eq!(s("custom://evil.com/login", "custom://bank.com/"), None);
    assert_eq!(s("custom://bank.com.evil.com/login", "custom://bank.com"), None);
    assert_eq!(s("custom://bank.com/login", "custom://bank.com"), Some(MAX_SCORE));
}

#[test]
fn pattern_mode() {
    let p = |page, pattern| score(page, &[(pattern, Pattern)]).is_some();
    assert!(!p("https://proton.me/", "*.proton.me"));
    assert!(!p("https://a.b.proton.me/path", "https://*.proton.me/*"));
    assert!(!p("https://a.proton.me/a/b/login", "https://*.proton.me/*/login"));
    assert!(p("https://a.proton.me/login", "https://*.proton.me/*"));
    assert!(p("https://a.b.c.proton.me/path", "**.proton.me/*"));
    assert!(p("https://a.b.c.proton.me/a/b/login", "**.proton.me/**/login"));
    assert!(p("https://a.b.c.proton.me/a/b/login", "*.*.*.proton.me/**/login"));
    assert!(p("https://a.b.proton.me", "**.proton.me"));
    assert!(p("https://proton.me", "proton.me"));
    assert!(p("https://proton.me/", "proton.me"));
    assert!(!p("https://proton.me/anything", "proton.me"));
    assert!(!p("http://a.proton.me/x", "https://*.proton.me/*"));
    assert!(!p("http://proton.me", "https://proton.me"));
    assert!(p("ftp://a.proton.me/x", "**.proton.me/*"));
    for pattern in ["**.acme.com", "https://**.acme.com/*", "**.acme.com/*"] {
        assert!(!p("https://evil.com/x.acme.com", pattern), "{pattern}");
        assert!(!p("https://evil.com/x.acme.com/p", pattern), "{pattern}");
    }
    assert!(p("https://anything.com/at/all", "**/**"));
    assert!(!p("https://anything.com/at/all", "**"));
    assert!(p("https://sub.proton.me", "*.Proton.ME"));
    assert!(p("https://sub.proton.me/login", "HTTPS://*.Proton.Me/*"));
    assert!(p("https://sub.proton.me/Login", "*.Proton.Me/Login"));
    assert!(!p("https://sub.proton.me/login", "*.Proton.Me/Login"));
    assert!(p("https://acme.com/index.html", "acme.com/*"));
    assert!(p("https://acme.com/a/b.c/login.php", "acme.com/*/*/login.php"));
    assert!(!p("https://acme.com/a/index.html", "acme.com/*"));
    // Wildcard inside a label
    assert!(p("https://subdomain.acme.com/path", "https://subdomain*.acme.com/*"));
    assert!(p("https://subdomain42.acme.com/path", "https://subdomain*.acme.com/*"));
    assert!(!p("https://acme.com/path", "https://subdomain*.acme.com/*"));
    // Page without scheme
    assert!(p("proton.me/login", "proton.me/login"));
    assert!(p("sub.proton.me", "https://*.proton.me"));
    // Query and fragment are ignored, ports must match
    assert!(p("https://acme.com/login?next=/home#top", "acme.com/login"));
    assert!(!p("https://acme.com:8443/login", "acme.com/*"));
    assert!(p("https://acme.com:8443/login", "acme.com:8443/*"));
    assert!(p("http://localhost:3000/login", "localhost:3000/**"));
    assert!(p("http://localhost:3000", "localhost:3000"));
    assert!(!p("http://localhost:3001/login", "localhost:3000/**"));
    assert!(!p("http://localhost/login", "localhost:3000/**"));
}

#[test]
fn regex_mode() {
    let r = |page, pattern| score(page, &[(pattern, RegularExpression)]).is_some();
    assert!(!r("https://proton.me/bbb", r"https:\/\/proton\.me\/a+"));
    assert!(r("https://proton.me/aaa", r"https:\/\/proton\.me\/a+"));
    assert!(r("https://proton.me/some/path", "proton"));
    assert!(r("https://PROTON.me", "proton"));
    // Unanchored patterns match anywhere in the URL, including path, query and fragment
    assert!(r("https://evil.com/proton.me", r"proton\.me"));
    assert!(r("https://proton.me/login?next=inbox", "next=inbox"));
    assert!(r("https://proton.me/login#2fa", "#2fa"));
    // Anchors pin the pattern to the full URL
    assert!(!r("https://evil.com/proton.me", r"^https://proton\.me/"));
    assert!(!r("https://proton.me.evil.com/", r"^https://proton\.me/$"));
    // Matching runs on the normalized URL: root path gets a trailing slash, missing scheme becomes https
    assert!(r("https://proton.me", r"^https://proton\.me/$"));
    assert!(r("proton.me", r"^https://proton\.me/$"));
    // Ports: a non-default port changes the destination, so it stays in the URL
    assert!(r("https://proton.me:8443/", r"^https://proton\.me:8443/$"));
    // 443 is the default https port (80 for http), so `https://proton.me:443/` is the same page as
    // `https://proton.me/`. WHATWG serialization drops a scheme's default port, like browsers do,
    // so the regex sees `https://proton.me/`.
    assert!(r("https://proton.me:443/", r"^https://proton\.me/$"));
    // Consequence: a pattern spelling out the default port can never match
    assert!(!r("https://proton.me:443/", r"^https://proton\.me:443/"));
    // Defaults are per scheme: 443 isn't http's default, so it stays
    assert!(r("http://proton.me:443/", r"^http://proton\.me:443/$"));
    // Alternation and character classes work
    assert!(r("https://proton.ch", r"proton\.(me|ch)"));
    assert!(!r("https://proton.com", r"proton\.(me|ch)"));
    assert!(r("https://mail7.proton.me", r"^https://mail\d\.proton\.me/"));
    // Patterns that fail to compile never match. "(proton" is an unclosed group, so it's invalid
    // everywhere. "(?=proton)" is a lookahead: valid in JS RegExp, but regex_lite doesn't support
    // lookaround, so the build returns Err and is_ok_and gives false instead of panicking.
    assert!(!r("https://proton.me", "(proton"));
    assert!(!r("https://proton.me", "(?=proton)"));
    // Huge patterns are rejected by the size limit: counted repetition is unrolled at compile time,
    // so (a{1000}){1000} becomes 1,000,000 `a` states, far over the 1 MiB cap. The build fails and
    // the pattern doesn't match, even though the `proton` branch alone would.
    assert!(!r("https://proton.me", "(a{1000}){1000}|proton"));
}

#[test]
fn exact_path_mode() {
    let e = |page, url| score(page, &[(url, ExactPath)]);
    assert_eq!(e("https://proton.me/path", "https://proton.me"), None);
    assert_eq!(e("https://proton.me/path", "https://proton.me/path"), Some(MAX_SCORE));
    assert_eq!(
        e("https://proton.me/path?param=value#hash", "https://proton.me/path"),
        Some(MAX_SCORE)
    );
    assert_eq!(e("https://[::1]:8443/a", "https://[::1]:8443/a"), Some(MAX_SCORE));
    // Custom schemes keep the host
    assert_eq!(e("custom://evil.com/login", "custom://bank.com/login"), None);
    assert_eq!(e("custom://bank.com/login", "custom://bank.com/login"), Some(MAX_SCORE));
}

#[test]
fn best_url_wins_and_results_are_sorted() {
    let items = vec![
        candidate(
            "weak",
            &[("https://example.com", Default), ("https://other.example.com", Default)],
        ),
        candidate("none", &[("https://proton.me", Default)]),
        candidate("exact", &[("https://login.example.com", Default)]),
        candidate("weak2", &[("https://example.com", Default)]),
    ];
    let res: Vec<UrlMatchResult> = match_urls("https://login.example.com", items, vec![]);
    let got: Vec<(&str, u32)> = res.iter().map(|r| (r.item_id.as_str(), r.score)).collect();
    // Ties keep input order
    assert_eq!(
        got,
        vec![("exact", MAX_SCORE), ("weak", MAX_SCORE - 1), ("weak2", MAX_SCORE - 1)]
    );
}

#[test]
fn browser_internal_pages_never_match() {
    for page in [
        "chrome://settings",
        "edge://settings",
        "opera://settings",
        "vivaldi://settings",
        "about:blank",
        "moz-extension://abc/popup.html",
        "safari-web-extension://abc/popup.html",
    ] {
        assert_eq!(default(page, &[page]), None, "{page}");
    }
}

#[test]
fn standalone_pattern_and_regex_validation() {
    assert_eq!(
        url_matches_pattern("*.proton.me", "https://account.proton.me"),
        Ok(true)
    );
    assert_eq!(url_matches_pattern("*.proton.me", "https://a.b.proton.me"), Ok(false));
    assert_eq!(
        url_matches_pattern("*.proton.me", "not a url"),
        Err(UrlMatchingError::InvalidUrl)
    );
    assert_eq!(
        url_matches_regex(r"^https://.*\.proton\.me/", "https://account.proton.me/login"),
        Ok(true)
    );
    assert_eq!(url_matches_regex("^http://", "https://proton.me"), Ok(false));
    assert!(matches!(
        url_matches_regex("(proton", "https://proton.me"),
        Err(UrlMatchingError::InvalidRegex(_))
    ));
    // Over the compiled size limit (see regex_mode): an error here, not a silent non-match
    assert!(matches!(
        url_matches_regex("(a{1000}){1000}|proton", "https://proton.me"),
        Err(UrlMatchingError::InvalidRegex(_))
    ));
    assert_eq!(url_matches_regex(".*", "not a url"), Err(UrlMatchingError::InvalidUrl));
}
