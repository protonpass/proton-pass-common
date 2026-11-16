//! Advanced URL matching: given login items and their per-URL autofill rules, find the ones matching a page.
//! Matches are ranked by a numeric score; regex rules run under a time budget.

use proton_pass_types::{AutofillUrl, AutofillUrlMode};
use public_suffix::{DEFAULT_PROVIDER, EffectiveTLDProvider};
use regex_lite::{Regex, RegexBuilder};
use std::sync::LazyLock;
use url::{Host, Url};
use web_time::{Duration, Instant};

pub const MAX_SCORE: u32 = 1000;
const MAX_HOSTNAME_LENGTH: usize = 253;
const REGEX_TIME_BUDGET: Duration = Duration::from_millis(100);
const REGEX_SIZE_LIMIT: usize = 1 << 20;

const UNSUPPORTED_SCHEMES: &[&str] = &[
    "file",
    "javascript",
    "data",
    "chrome-extension",
    "chrome",
    "brave",
    "edge",
    "moz-extension",
    "about",
];

/// https://urlregex.com
static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"((([A-Za-z]{3,9}:(?://)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:/[\+~%/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_]*)#?(?:[\.!/\\\w]*))?)",
    )
    .expect("valid URL regex")
});

static PATTERN_PROTOCOL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[a-z][a-z\d+.-]*://").expect("valid protocol regex"));

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlMatchingCandidate {
    pub item_id: String,
    pub share_id: String,
    pub url_mode: Vec<AutofillUrl>,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlMatchResult {
    pub item_id: String,
    pub share_id: String,
    /// `MAX_SCORE` for an exact match, lower the further the hosts are apart.
    pub score: u32,
}

/// Returns the candidates matching `url`, best score first.
/// Sort is stable: pass candidates sorted by last use time to break ties.
pub fn match_urls(
    url: &str,
    candidates: Vec<UrlMatchingCandidate>,
    private_domains: Vec<String>,
) -> Vec<UrlMatchResult> {
    let Some(page) = parse_url(url, &private_domains) else {
        return vec![];
    };

    let mut results: Vec<UrlMatchResult> = candidates
        .into_iter()
        .filter_map(|c| {
            score_item(&c.url_mode, &page).map(|score| UrlMatchResult {
                item_id: c.item_id,
                share_id: c.share_id,
                score,
            })
        })
        .collect();
    results.sort_by_key(|r| std::cmp::Reverse(r.score));
    results
}

/// Best score of the item's URLs, `None` if none matches or a `Never` rule blocks this exact page.
fn score_item(urls: &[AutofillUrl], page: &ParsedUrl) -> Option<u32> {
    let blocked = urls.iter().any(|u| {
        u.mode == AutofillUrlMode::Never && parse_url(&u.url, &[]).is_some_and(|p| p.clean_url == page.clean_url)
    });
    if blocked {
        return None;
    }

    let mut best = None;
    for u in urls {
        best = best.max(score_url(u, page));
        if best == Some(MAX_SCORE) {
            break;
        }
    }
    best
}

fn score_url(rule: &AutofillUrl, page: &ParsedUrl) -> Option<u32> {
    let matched = match rule.mode {
        AutofillUrlMode::Never => false,
        AutofillUrlMode::Pattern => match_pattern(&rule.url, page),
        AutofillUrlMode::RegularExpression => match_regex(&rule.url, page),
        mode => {
            let item = parse_url(&rule.url, &[])?;
            match mode {
                AutofillUrlMode::Default => return match_default(&item, page),
                AutofillUrlMode::Exact => match_exact(&item, page),
                AutofillUrlMode::ExactPath => item.clean_url == page.clean_url,
                AutofillUrlMode::StartWith => page.clean_url.starts_with(&item.clean_url),
                _ => false,
            }
        }
    };
    matched.then_some(MAX_SCORE)
}

fn share_port_and_protocol(item: &ParsedUrl, page: &ParsedUrl) -> bool {
    let share_port = page.port.is_none() || item.port == page.port;
    let share_protocol = page.protocol == "https:" || item.protocol == page.protocol;
    share_port && share_protocol
}

fn match_exact(item: &ParsedUrl, page: &ParsedUrl) -> bool {
    share_port_and_protocol(item, page) && item.resolve_subdomain() == page.resolve_subdomain()
}

/// Same host, parent, child or sibling under the same root domain.
fn match_default(item: &ParsedUrl, page: &ParsedUrl) -> Option<u32> {
    if !share_port_and_protocol(item, page) {
        return None;
    }
    let (item_sub, page_sub) = (item.resolve_subdomain(), page.resolve_subdomain());
    // Parent/child/sibling all share the root domain. A bare public suffix (e.g. a saved `com`) has no
    // root domain, so it never matches its children.
    (item_sub == page_sub || item.domain == page.domain)
        .then(|| MAX_SCORE.saturating_sub(label_distance(item_sub, page_sub)))
}

/// Labels compared from the right: each differing label and each extra label costs 1.
fn label_distance(a: &str, b: &str) -> u32 {
    let a: Vec<&str> = a.rsplit('.').collect();
    let b: Vec<&str> = b.rsplit('.').collect();
    let mismatches = a.iter().zip(&b).filter(|(x, y)| x != y).count();
    (mismatches + a.len().abs_diff(b.len())) as u32
}

/// A leading scheme pins the protocol, the host glob must match the hostname alone (anti-spoofing),
/// then host + path glob must match the scheme-stripped page URL.
fn match_pattern(pattern: &str, page: &ParsedUrl) -> bool {
    let pinned = PATTERN_PROTOCOL_REGEX.find(pattern).map(|m| m.as_str());
    if let Some(pinned) = pinned
        && !page.url.starts_with(&pinned.to_lowercase())
    {
        return false;
    }

    let pattern = &pattern[pinned.map_or(0, str::len)..];
    // `protocol` is `scheme:`, the sanitized URL always continues with `//`
    let target = &page.url[page.protocol.len() + 2..];

    let (host_part, path_part) = pattern.split_at(pattern.find('/').unwrap_or(pattern.len()));
    let host_part = host_part.to_lowercase();
    if !glob_matches(&host_part, &page.hostname) {
        return false;
    }
    path_part.is_empty() || glob_matches(&format!("{host_part}{path_part}"), target)
}

/// `*` matches within a segment (no `.` or `/`), `**` matches across separators. Case-sensitive, anchored.
fn glob_matches(glob: &str, input: &str) -> bool {
    let mut regex = String::from("^");
    for (i, part) in glob.split("**").enumerate() {
        if i > 0 {
            regex.push_str(".*");
        }
        let escaped: Vec<String> = part.split('*').map(regex_lite::escape).collect();
        regex.push_str(&escaped.join(r"[^./]*"));
    }
    regex.push('$');
    Regex::new(&regex).is_ok_and(|r| r.is_match(input))
}

/// Unanchored and case-insensitive against the page URL.
/// `regex-lite` is linear-time so it can't hang, but a big pattern on a long URL can still be slow:
/// anything over the time budget counts as no match.
fn match_regex(pattern: &str, page: &ParsedUrl) -> bool {
    let start = Instant::now();
    let matched = RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .is_ok_and(|r| r.is_match(&page.url));
    matched && start.elapsed() <= REGEX_TIME_BUDGET
}

#[derive(Debug)]
struct ParsedUrl {
    /// Root domain, or the hostname for localhost and IPs. Never empty.
    domain: String,
    /// Full hostname when there is a subdomain other than `www`.
    subdomain: Option<String>,
    hostname: String,
    /// e.g. `https:`
    protocol: String,
    port: Option<u16>,
    /// The sanitized URL, so it always has a scheme even when the input didn't.
    url: String,
    /// origin + path
    clean_url: String,
}

impl ParsedUrl {
    fn resolve_subdomain(&self) -> &str {
        self.subdomain.as_deref().unwrap_or(&self.domain)
    }
}

/// WHATWG parsing, retrying with `https://` when the input doesn't parse.
fn sanitize_url(input: &str) -> Option<Url> {
    fn parse(candidate: &str) -> Result<Option<Url>, url::ParseError> {
        let candidate = candidate.trim();
        if candidate.chars().any(char::is_whitespace) {
            return Ok(None);
        }
        let url = Url::parse(candidate)?;
        if UNSUPPORTED_SCHEMES.contains(&url.scheme()) {
            return Ok(None);
        }
        let hostname_ok = url.host_str().unwrap_or_default().len() <= MAX_HOSTNAME_LENGTH;
        Ok((hostname_ok && URL_REGEX.is_match(url.as_str())).then_some(url))
    }

    if input.is_empty() {
        return None;
    }
    match parse(input) {
        Ok(url) => url,
        Err(_) if !input.starts_with("http://") && !input.starts_with("https://") => {
            parse(&format!("https://{input}")).ok().flatten()
        }
        Err(_) => None,
    }
}

/// `None` when there is no hostname. Public suffix semantics only ever come from the
/// WHATWG hostname (SECBTY-1891).
fn parse_url(input: &str, private_domains: &[String]) -> Option<ParsedUrl> {
    let url = sanitize_url(input)?;
    let hostname = url.host_str().filter(|h| !h.is_empty())?.to_string();

    let (mut domain, mut subdomain) = match url.host() {
        Some(Host::Domain(host)) => match DEFAULT_PROVIDER.effective_tld_plus_one(host) {
            Ok(d) => {
                let sub = host
                    .strip_suffix(d)
                    .and_then(|s| s.strip_suffix('.'))
                    .filter(|s| !s.is_empty());
                (Some(d.to_string()), sub.map(str::to_string))
            }
            Err(_) => (None, None),
        },
        _ => (None, None),
    };

    if let Some(d) = &domain
        && let Some((d, sub)) = find_private_domain(d, subdomain.as_deref(), private_domains)
    {
        domain = Some(d);
        subdomain = sub;
    }

    Some(ParsedUrl {
        domain: domain.unwrap_or_else(|| hostname.clone()),
        subdomain: subdomain.filter(|s| s != "www").map(|_| hostname.clone()),
        protocol: format!("{}:", url.scheme()),
        port: url.port(),
        clean_url: format!("{}{}", url.origin().ascii_serialization(), url.path()),
        url: url.into(),
        hostname,
    })
}

/// Walks from the root domain outwards: the first combination in
/// `private_domains` becomes the public suffix. Returns the new (domain, subdomain).
fn find_private_domain(
    domain: &str,
    subdomain: Option<&str>,
    private_domains: &[String],
) -> Option<(String, Option<String>)> {
    if private_domains.is_empty() {
        return None;
    }
    let mut labels: Vec<&str> = subdomain.map(|s| s.rsplit('.').collect()).unwrap_or_default();
    let mut suffix = domain.to_string();
    loop {
        if private_domains.contains(&suffix) {
            let (new_domain, rest) = match labels.split_first() {
                Some((label, rest)) => (format!("{label}.{suffix}"), rest),
                None => (suffix, &[][..]),
            };
            let rest: Vec<&str> = rest.iter().rev().copied().collect();
            return Some((new_domain, Some(rest.join(".")).filter(|s| !s.is_empty())));
        }
        if labels.is_empty() {
            return None;
        }
        suffix = format!("{}.{suffix}", labels.remove(0));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_url_domain_and_subdomain() {
        let p = parse_url("https://www.account.secure.github.com/path", &[]).unwrap();
        assert_eq!(p.domain, "github.com");
        assert_eq!(p.subdomain.as_deref(), Some("www.account.secure.github.com"));

        let p = parse_url("https://www.github.com", &[]).unwrap();
        assert_eq!(p.domain, "github.com");
        assert_eq!(p.subdomain, None);
        assert_eq!(p.resolve_subdomain(), "github.com");
    }

    #[test]
    fn parse_url_psl_private_suffix() {
        let p = parse_url("https://sub.admin.github.io", &[]).unwrap();
        assert_eq!(p.domain, "admin.github.io");
        assert_eq!(p.subdomain.as_deref(), Some("sub.admin.github.io"));
    }

    #[test]
    fn parse_url_ip_and_localhost() {
        let p = parse_url("http://192.168.1.1/path", &[]).unwrap();
        assert_eq!(p.domain, "192.168.1.1");
        assert_eq!(p.subdomain, None);

        let p = parse_url("http://localhost:3001", &[]).unwrap();
        assert_eq!(p.domain, "localhost");
        assert_eq!(p.port, Some(3001));
    }

    #[test]
    fn parse_url_backslash_spoofing() {
        // SECBTY-1891
        let p = parse_url(r"https://evil.com\@bank.com/", &[]).unwrap();
        assert_eq!(p.hostname, "evil.com");
        assert_eq!(p.domain, "evil.com");
    }

    #[test]
    fn parse_url_custom_private_domains() {
        let private = vec!["example.com".to_string()];
        let p = parse_url("https://a.b.example.com", &private).unwrap();
        assert_eq!(p.domain, "b.example.com");
        assert_eq!(p.subdomain.as_deref(), Some("a.b.example.com"));

        let p = parse_url("https://b.example.com", &private).unwrap();
        assert_eq!(p.domain, "b.example.com");
        assert_eq!(p.subdomain, None);

        let p = parse_url("https://www.b.example.com", &private).unwrap();
        assert_eq!(p.subdomain, None);
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_url("proton.me").unwrap().as_str(), "https://proton.me/");
        assert_eq!(sanitize_url("https:/proton.me").unwrap().as_str(), "https://proton.me/");
        assert_eq!(sanitize_url("proton.me  ").unwrap().as_str(), "https://proton.me/");
        assert!(sanitize_url("proton.me  /").is_none());
        assert!(sanitize_url("").is_none());
        assert!(sanitize_url(" ").is_none());
        assert!(sanitize_url("javascript:alert(1)").is_none());
        assert!(sanitize_url("chrome-extension://abc").is_none());
        assert!(sanitize_url(&format!("https://{}.com", "a".repeat(250))).is_none());
        assert_eq!(
            sanitize_url("https://www.proton.me:8080/a?b=c").unwrap().as_str(),
            "https://www.proton.me:8080/a?b=c"
        );
    }

    #[test]
    fn glob() {
        assert!(glob_matches("*.proton.me", "a.proton.me"));
        assert!(!glob_matches("*.proton.me", "a.b.proton.me"));
        assert!(glob_matches("**.proton.me", "a.b.proton.me"));
        assert!(!glob_matches("*.proton.me", "proton.me"));
        assert!(glob_matches("a+b(c)?.me", "a+b(c)?.me"));
    }

    #[test]
    fn distance() {
        assert_eq!(label_distance("pm.me", "a.b.pm.me"), 2);
        assert_eq!(label_distance("other.example.com", "login.example.com"), 1);
        assert_eq!(label_distance("example.com", "example.com"), 0);
    }
}
