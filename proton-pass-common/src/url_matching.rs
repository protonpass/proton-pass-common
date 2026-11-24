//! Advanced URL matching: given login items and their per-URL autofill rules, find the ones matching a page.
//! Matches are ranked by a numeric score.

use proton_pass_derive::{Error, ffi_error};
use proton_pass_types::{AutofillUrl, AutofillUrlMode};
use public_suffix::{DEFAULT_PROVIDER, EffectiveTLDProvider};
use regex_lite::{Regex, RegexBuilder};
use std::sync::LazyLock;
use url::{Host, Url};

pub const MAX_SCORE: u32 = 1000;
/// Max length of a domain name in text form (RFC 1035).
const MAX_HOSTNAME_LENGTH: usize = 253;
/// Cap compiled size of user-supplied patterns (regex-lite default is 10 MiB); bounds both memory and linear-time match cost.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Local, script, inline-data and browser-internal pages (settings, extensions, new tab). They have no
/// real website to autofill, so `sanitize_url` rejects them and they never match any item.
const UNSUPPORTED_SCHEMES: &[&str] = &[
    "file",
    "javascript",
    "data",
    "view-source",
    // Chromium-based browsers: Chrome, Brave, Edge, Opera, Vivaldi, Arc, Samsung Internet, Yandex
    "chrome",
    "chrome-extension",
    "brave",
    "edge",
    "opera",
    "vivaldi",
    "arc",
    "internet",
    "browser",
    // Firefox
    "about",
    "moz-extension",
    "resource",
    // Safari
    "safari-web-extension",
];

static PATTERN_SCHEME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[a-z][a-z\d+.-]*://").expect("valid scheme regex"));

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

/// Returns the candidates matching `url`, best first. Ties keep input order.
///
/// `private_domains`: extra domains treated as public suffixes, on top of the
/// public suffix list. With `example.com` listed, `a.example.com` and
/// `b.example.com` are separate sites and don't match each other.
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
            score_item(&c.url_mode, &page, &private_domains).map(|score| UrlMatchResult {
                item_id: c.item_id,
                share_id: c.share_id,
                score,
            })
        })
        .collect();
    results.sort_by_key(|r| std::cmp::Reverse(r.score));
    results
}

#[ffi_error]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UrlMatchingError {
    /// The sample URL has no usable hostname or an unsupported scheme.
    InvalidUrl,
    /// The regex doesn't compile or is too large; carries the compiler message.
    InvalidRegex(String),
}

fn parse_sample_url(url: &str) -> Result<ParsedUrl, UrlMatchingError> {
    parse_url(url, &[]).ok_or(UrlMatchingError::InvalidUrl)
}

/// Whether `url` matches a `Pattern` mode rule, for validating user input against a sample URL.
pub fn url_matches_pattern(pattern: &str, url: &str) -> Result<bool, UrlMatchingError> {
    Ok(match_pattern(pattern, &parse_sample_url(url)?))
}

/// Whether `url` matches a `RegularExpression` mode rule, for validating user input against a sample URL.
pub fn url_matches_regex(regex: &str, url: &str) -> Result<bool, UrlMatchingError> {
    let page = parse_sample_url(url)?;
    let regex = build_regex(regex).map_err(|e| UrlMatchingError::InvalidRegex(e.to_string()))?;
    Ok(regex.is_match(&page.url))
}

/// Best score of the item's URLs, `None` if none matches or a `Never` rule blocks this exact page.
fn score_item(urls: &[AutofillUrl], page: &ParsedUrl, private_domains: &[String]) -> Option<u32> {
    let blocked = urls.iter().any(|u| {
        u.mode == AutofillUrlMode::Never
            && parse_url(&u.url, private_domains).is_some_and(|p| p.clean_url == page.clean_url)
    });
    if blocked {
        return None;
    }

    let mut best = None;
    for u in urls {
        best = best.max(score_url(u, page, private_domains));
        if best == Some(MAX_SCORE) {
            break;
        }
    }
    best
}

fn score_url(rule: &AutofillUrl, page: &ParsedUrl, private_domains: &[String]) -> Option<u32> {
    let matched = match rule.mode {
        AutofillUrlMode::Never => false,
        AutofillUrlMode::Pattern => match_pattern(&rule.url, page),
        AutofillUrlMode::RegularExpression => match_regex(&rule.url, page),
        mode => {
            let item = parse_url(&rule.url, private_domains)?;
            match mode {
                AutofillUrlMode::Default => return match_default(&item, page),
                AutofillUrlMode::Exact => match_exact(&item, page),
                AutofillUrlMode::ExactPath => item.clean_url == page.clean_url,
                // Compare origins, not a string prefix: `bank.com.evil.com` starts with `bank.com`.
                AutofillUrlMode::StartWith => {
                    (&item.protocol, &item.hostname, item.port) == (&page.protocol, &page.hostname, page.port)
                        && page.path.starts_with(&item.path)
                }
                _ => false,
            }
        }
    };
    matched.then_some(MAX_SCORE)
}

fn share_port_and_protocol(item: &ParsedUrl, page: &ParsedUrl) -> bool {
    let share_port = page.port.is_none() || item.port == page.port;
    let share_protocol = item.protocol == page.protocol || (page.protocol == "https:" && item.protocol == "http:");
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
    (item_sub == page_sub || item.domain == page.domain).then(|| domain_closeness(item_sub, page_sub))
}

/// How close two domains are: `MAX_SCORE` when identical, minus 1 for each label (compared from the
/// right) that differs or exists on only one side.
///
/// - `example.com` vs `example.com` → `MAX_SCORE`
/// - `login.example.com` vs `a.b.example.com` → `MAX_SCORE - 2` (`login` ≠ `b`, extra `a`)
fn domain_closeness(a: &str, b: &str) -> u32 {
    let a: Vec<&str> = a.rsplit('.').collect();
    let b: Vec<&str> = b.rsplit('.').collect();
    let mismatches = a.iter().zip(&b).filter(|(x, y)| x != y).count();
    MAX_SCORE.saturating_sub((mismatches + a.len().abs_diff(b.len())) as u32)
}

/// Pattern shape: optional scheme, host glob, optional port, path glob. Query and fragment are ignored.
fn match_pattern(pattern: &str, page: &ParsedUrl) -> bool {
    let scheme = PATTERN_SCHEME_REGEX.find(pattern).map(|m| m.as_str());
    if let Some(scheme) = scheme
        && !page.url.starts_with(&scheme.to_lowercase())
    {
        return false;
    }

    let pattern = &pattern[scheme.map_or(0, str::len)..];
    let (host_part, path_part) = pattern.split_at(pattern.find('/').unwrap_or(pattern.len()));
    let (host_part, port) = host_part
        .split_once(':')
        .map_or((host_part, None), |(h, p)| (h, Some(p)));
    if !glob_matches(&host_part.to_lowercase(), &page.hostname, '.') {
        return false;
    }
    // shortcut: an explicit default port (`:443` on https) never matches, since `Url::port` drops it.
    // Like Default mode, a page on a non-default port only matches a pattern naming that port.
    if page.port.map(|p| p.to_string()).as_deref() != port {
        return false;
    }
    path_part.is_empty() || glob_matches(path_part, &page.path, '/')
}

/// Matches `input` against `glob` by converting the glob into an anchored (`^...$`), case-sensitive regex:
/// - `**` becomes `.*`, which can match across separators.
/// - `*` becomes `[^<separator>]*`, which stays inside one segment.
/// - Everything else is regex-escaped, so it matches literally.
///
/// The separator is `.` for hosts and `/` for paths. So `*.proton.me` matches `a.proton.me` but not
/// `a.b.proton.me`, and `/*` matches `/index.html` (dots are allowed in a path segment).
fn glob_matches(glob: &str, input: &str, separator: char) -> bool {
    let mut regex = String::from("^");
    for (i, part) in glob.split("**").enumerate() {
        if i > 0 {
            regex.push_str(".*");
        }
        let escaped: Vec<String> = part.split('*').map(regex_lite::escape).collect();
        regex.push_str(&escaped.join(&format!("[^{separator}]*")));
    }
    regex.push('$');
    Regex::new(&regex).is_ok_and(|r| r.is_match(input))
}

fn build_regex(pattern: &str) -> Result<Regex, regex_lite::Error> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// An invalid regex never matches.
fn match_regex(pattern: &str, page: &ParsedUrl) -> bool {
    build_regex(pattern).is_ok_and(|r| r.is_match(&page.url))
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
    /// e.g. `/login`, without query or fragment
    path: String,
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
        Ok(hostname_ok.then_some(url))
    }

    if input.is_empty() {
        return None;
    }
    if is_host_port(input.trim()) {
        return parse(&format!("https://{}", input.trim())).ok().flatten();
    }
    match parse(input) {
        Ok(url) => url,
        Err(_) if !input.starts_with("http://") && !input.starts_with("https://") => {
            parse(&format!("https://{input}")).ok().flatten()
        }
        Err(_) => None,
    }
}

/// Detects scheme-less `host:port` input, which WHATWG would otherwise parse as scheme `host` with path `port`
/// (`localhost:3000` becomes scheme `localhost`, no host).
///
/// - `true`: `localhost:3000`, `example.com:8080/login`, `example.com:8080?q=1`
/// - `false`: `https://example.com:8080` (has a scheme), `mailto:a@b.com` (not a port), `tel:1234` (no dot, not localhost)
///
/// Host characters aren't checked here: `Url::parse` validates them once `https://` is prepended.
fn is_host_port(input: &str) -> bool {
    let Some((host, rest)) = input.split_once(':') else {
        return false;
    };
    let port = rest.split(['/', '?', '#']).next().unwrap_or_default();
    (host.eq_ignore_ascii_case("localhost") || host.contains('.'))
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
}

/// `None` when there is no hostname.
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
        && let Some(split) = find_private_domain(d, subdomain.as_deref(), private_domains)
    {
        domain = Some(split.domain);
        subdomain = split.subdomain;
    }

    Some(ParsedUrl {
        domain: domain.unwrap_or_else(|| hostname.clone()),
        subdomain: subdomain.filter(|s| s != "www").map(|_| hostname.clone()),
        protocol: format!("{}:", url.scheme()),
        port: url.port(),
        path: url.path().to_string(),
        // Not `url.origin()`: it is opaque (`null`) for custom schemes, which would drop the host.
        clean_url: format!(
            "{}://{hostname}{}{}",
            url.scheme(),
            url.port().map(|p| format!(":{p}")).unwrap_or_default(),
            url.path()
        ),
        url: url.into(),
        hostname,
    })
}

/// Domain and subdomain after re-splitting a host on a private domain.
#[derive(Debug, PartialEq)]
struct PrivateDomainSplit {
    domain: String,
    subdomain: Option<String>,
}

/// Walks from the root domain outwards: the first combination in
/// `private_domains` becomes the public suffix. Returns the new domain and subdomain.
///
/// The subdomain's dot-separated parts are added to the domain one at a time,
/// starting with the one closest to it.
///
/// Example: `foo.bar.example.com` gives domain `example.com` and subdomain `foo.bar`.
/// - `private_domains = ["example.com"]`: `example.com` is a suffix, so the result is
///   domain `bar.example.com`, subdomain `Some("foo")`.
/// - `private_domains = ["bar.example.com"]`: the walk goes `example.com` (no match),
///   then `bar.example.com` (match), so the result is domain `foo.bar.example.com`, subdomain `None`.
/// - `private_domains = ["other.com"]`: no match, so the result is `None`.
fn find_private_domain(
    domain: &str,
    subdomain: Option<&str>,
    private_domains: &[String],
) -> Option<PrivateDomainSplit> {
    if private_domains.is_empty() {
        return None;
    }
    let mut subdomain_parts: Vec<&str> = subdomain.map(|s| s.rsplit('.').collect()).unwrap_or_default();
    let mut suffix = domain.to_string();
    loop {
        if private_domains.contains(&suffix) {
            let (new_domain, rest) = match subdomain_parts.split_first() {
                Some((part, rest)) => (format!("{part}.{suffix}"), rest),
                None => (suffix, &[][..]),
            };
            let rest: Vec<&str> = rest.iter().rev().copied().collect();
            return Some(PrivateDomainSplit {
                domain: new_domain,
                subdomain: Some(rest.join(".")).filter(|s| !s.is_empty()),
            });
        }
        if subdomain_parts.is_empty() {
            return None;
        }
        suffix = format!("{}.{suffix}", subdomain_parts.remove(0));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn is_host_port_detects_scheme_less_host_and_port() {
        for input in [
            "localhost:3000",
            "LOCALHOST:3000",
            "example.com:8080",
            "example.com:8080/login",
            "example.com:8080?q=1",
            "example.com:8080#top",
        ] {
            assert!(is_host_port(input), "{input}");
        }
    }

    #[test]
    fn is_host_port_rejects_schemes_and_non_ports() {
        for input in [
            "example.com",
            "example.com:",
            "example.com:80a",
            "https://example.com:8080",
            "mailto:a@b.com",
            "tel:1234",
        ] {
            assert!(!is_host_port(input), "{input}");
        }
    }

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
    fn private_domain_split() {
        // No private domains, or none matching
        assert_eq!(find_private_domain("example.com", Some("foo.bar"), &[]), None);
        assert_eq!(
            find_private_domain("example.com", Some("foo.bar"), &["other.com".to_string()]),
            None
        );
        assert_eq!(
            find_private_domain("example.com", None, &["other.com".to_string()]),
            None
        );
        // Partial label match is not a suffix match
        assert_eq!(
            find_private_domain("example.com", Some("foo.bar"), &["ar.example.com".to_string()]),
            None
        );

        // Match on the root domain: closest part joins the domain, the rest stays in order
        assert_eq!(
            find_private_domain("example.com", Some("a.b.c"), &["example.com".to_string()]),
            Some(PrivateDomainSplit {
                domain: "c.example.com".to_string(),
                subdomain: Some("a.b".to_string())
            })
        );
        assert_eq!(
            find_private_domain("example.com", Some("foo"), &["example.com".to_string()]),
            Some(PrivateDomainSplit {
                domain: "foo.example.com".to_string(),
                subdomain: None
            })
        );
        // Match with no subdomain left to promote
        assert_eq!(
            find_private_domain("example.com", None, &["example.com".to_string()]),
            Some(PrivateDomainSplit {
                domain: "example.com".to_string(),
                subdomain: None
            })
        );

        // Match one level out
        assert_eq!(
            find_private_domain("example.com", Some("foo.bar"), &["bar.example.com".to_string()]),
            Some(PrivateDomainSplit {
                domain: "foo.bar.example.com".to_string(),
                subdomain: None
            })
        );
        assert_eq!(
            find_private_domain("example.com", Some("a.b.foo.bar"), &["bar.example.com".to_string()]),
            Some(PrivateDomainSplit {
                domain: "foo.bar.example.com".to_string(),
                subdomain: Some("a.b".to_string())
            })
        );
        // Match consuming the whole host
        assert_eq!(
            find_private_domain("example.com", Some("foo.bar"), &["foo.bar.example.com".to_string()]),
            Some(PrivateDomainSplit {
                domain: "foo.bar.example.com".to_string(),
                subdomain: None
            })
        );

        // The walk starts at the root, so the shortest matching suffix wins
        assert_eq!(
            find_private_domain(
                "example.com",
                Some("a.b.c"),
                &["c.example.com".to_string(), "example.com".to_string()]
            ),
            Some(PrivateDomainSplit {
                domain: "c.example.com".to_string(),
                subdomain: Some("a.b".to_string())
            })
        );
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
        assert!(glob_matches("*.proton.me", "a.proton.me", '.'));
        assert!(!glob_matches("*.proton.me", "a.b.proton.me", '.'));
        assert!(glob_matches("**.proton.me", "a.b.proton.me", '.'));
        assert!(!glob_matches("*.proton.me", "proton.me", '.'));
        assert!(glob_matches("a+b(c)?.me", "a+b(c)?.me", '.'));
        assert!(glob_matches("/*", "/index.html", '/'));
        assert!(!glob_matches("/*", "/a/index.html", '/'));
    }

    #[test]
    fn closeness() {
        assert_eq!(domain_closeness("pm.me", "a.b.pm.me"), MAX_SCORE - 2);
        assert_eq!(
            domain_closeness("other.example.com", "login.example.com"),
            MAX_SCORE - 1
        );
        assert_eq!(domain_closeness("example.com", "example.com"), MAX_SCORE);
    }
}
