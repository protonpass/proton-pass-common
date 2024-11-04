use public_suffix::DEFAULT_PROVIDER;
use std::net::IpAddr;
use std::str::FromStr;
use url::Url;

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq)]
pub enum ParseHostError {
    CannotGetDomainFromUrl,
    EmptyHost,
    EmptyUrl,
    HostIsTld,
    ParseUrlError,
    InvalidUrlError,
}

type Result<T> = std::result::Result<T, ParseHostError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostInfo {
    Host {
        protocol: String,
        subdomain: Option<String>,
        domain: String,
        tld: Option<String>,
    },
    Ip {
        ip: String,
    },
}

const FORBIDDEN_SCHEMES: &[&str] = &["javascript:", "data:", "file:", "about:", "blob:"];

pub fn parse(url: &str) -> Result<HostInfo> {
    let domain = get_domain(url)?;
    let protocol = get_protocol(url).unwrap_or_else(|_| "https".to_string());
    get_host_info_from_domain(&protocol, &domain)
}

fn sanitize(url: &str) -> Result<String> {
    if url.trim().is_empty() {
        return Err(ParseHostError::EmptyUrl);
    }
    if url.chars().all(|c| !c.is_alphanumeric()) {
        return Err(ParseHostError::InvalidUrlError);
    }

    for &forbidden in FORBIDDEN_SCHEMES.iter() {
        if url.starts_with(forbidden) {
            return Err(ParseHostError::InvalidUrlError);
        }
    }

    let url_with_scheme = if !url.contains("://") {
        format!("https://{}", url)
    } else {
        url.to_string()
    };

    let mut parsed = Url::parse(&url_with_scheme).map_err(|_| ParseHostError::ParseUrlError)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ParseHostError::ParseUrlError)?
        .to_string();

    if host.ends_with('.') {
        let host_without_trailing_dot = Some(host.trim_end_matches('.'));
        parsed
            .set_host(host_without_trailing_dot)
            .map_err(|_| ParseHostError::ParseUrlError)?;
    }

    Ok(parsed.as_str().to_string())
}

fn sanitize_and_parse(url: &str) -> Result<Url> {
    let sanitized_url = sanitize(url)?;
    let parsed = Url::parse(&sanitized_url).map_err(|_| ParseHostError::ParseUrlError)?;
    Ok(parsed)
}

fn get_protocol(url: &str) -> Result<String> {
    let parsed = sanitize_and_parse(url)?;
    Ok(parsed.scheme().to_string())
}

fn get_domain(url: &str) -> Result<String> {
    let parsed = sanitize_and_parse(url)?;
    let domain = parsed
        .host_str()
        .map(|host| host.to_string())
        .ok_or_else(|| ParseHostError::InvalidUrlError)?;

    let allowed_chars = ['.', '-', '_'];
    for c in domain.chars() {
        if !c.is_alphanumeric() && !allowed_chars.contains(&c) {
            return Err(ParseHostError::InvalidUrlError);
        }
    }

    Ok(domain)
}

fn get_host_info_from_domain(protocol: &str, domain: &str) -> Result<HostInfo> {
    if IpAddr::from_str(domain).is_ok() {
        Ok(HostInfo::Ip { ip: domain.to_string() })
    } else {
        parse_host_info(protocol, domain)
    }
}

fn parse_host_info(protocol: &str, domain: &str) -> Result<HostInfo> {
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.is_empty() {
        return Err(ParseHostError::EmptyHost);
    } else if parts.len() == 1 {
        return Ok(HostInfo::Host {
            protocol: protocol.to_string(),
            subdomain: None,
            domain: domain.to_string(),
            tld: None,
        });
    }

    // Find the widest match that is a TLD
    for i in 0..parts.len() {
        let portion = parts[i..].join(".");
        if DEFAULT_PROVIDER.is_effective_tld(&portion) {
            if i == 0 {
                return Err(ParseHostError::HostIsTld);
            } else {
                let res = host_with_tld(protocol, &parts, i, &portion);
                return Ok(res);
            }
        }
    }

    // No TLD found
    let res = host_without_tld(protocol, &parts);
    Ok(res)
}

fn host_with_tld(protocol: &str, parts: &[&str], tld_starting_part: usize, tld: &str) -> HostInfo {
    let domain = parts[tld_starting_part - 1].to_string();
    let subdomain = if tld_starting_part == 1 {
        None
    } else {
        Some(parts[0..tld_starting_part - 1].join("."))
    };

    HostInfo::Host {
        protocol: protocol.to_string(),
        subdomain,
        domain,
        tld: Some(tld.to_string()),
    }
}

fn host_without_tld(protocol: &str, parts: &[&str]) -> HostInfo {
    let tld = parts.last().unwrap().to_string();

    if parts.len() > 2 {
        let subdomain = Some(parts[0..parts.len() - 2].join("."));
        HostInfo::Host {
            protocol: protocol.to_string(),
            subdomain,
            domain: parts[parts.len() - 2].to_string(),
            tld: Some(tld),
        }
    } else {
        HostInfo::Host {
            protocol: protocol.to_string(),
            subdomain: None,
            domain: parts[0].to_string(),
            tld: Some(tld),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_simple_domain() {
        let url = "https://example.com";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host {
                protocol,
                subdomain,
                domain,
                tld,
            } => {
                assert_eq!(protocol, "https");
                assert_eq!(subdomain, None);
                assert_eq!(domain, "example");
                assert_eq!(tld, Some("com".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn parse_with_subdomain() {
        let url = "http://sub.example.co.uk";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host {
                protocol,
                subdomain,
                domain,
                tld,
            } => {
                assert_eq!(protocol, "http");
                assert_eq!(subdomain, Some("sub".to_string()));
                assert_eq!(domain, "example");
                assert_eq!(tld, Some("co.uk".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn parse_ip_address() {
        let url = "https://192.168.0.1";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Ip { ip } => {
                assert_eq!(ip, "192.168.0.1");
            }
            _ => panic!("Expected Ip variant"),
        }
    }

    #[test]
    fn parse_domain_without_tld() {
        let url = "https://kokejtoe";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host {
                protocol,
                subdomain,
                domain,
                tld,
            } => {
                assert_eq!(protocol, "https");
                assert_eq!(subdomain, None);
                assert_eq!(domain, "kokejtoe");
                assert_eq!(tld, None);
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn parse_url_with_port() {
        let url = "http://example.com:8080";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host { domain, tld, .. } => {
                assert_eq!(domain, "example");
                assert_eq!(tld, Some("com".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn parse_url_with_path() {
        let url = "https://example.com/path/to/resource";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host { domain, tld, .. } => {
                assert_eq!(domain, "example");
                assert_eq!(tld, Some("com".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn parse_invalid_url() {
        let url = "not a url";
        let result = parse(url);

        assert!(result.is_err());
    }

    #[test]
    fn parse_unicode_domain() {
        let url = "https://例子.测试";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host { domain, tld, .. } => {
                // Convert to punycode
                assert_eq!(domain, "xn--fsqu00a");
                assert_eq!(tld, Some("xn--0zwm56d".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn empty_string_should_return_error() {
        let url = "";
        let result = parse(url);

        assert!(result.is_err());
    }

    #[test]
    fn symbols_string_should_error() {
        let url = ".$%";
        let result = parse(url);

        assert!(result.is_err());
    }

    #[test]
    fn can_only_contain_allowed_symbols() {
        let url = "a!b";
        let result = parse(url);

        assert!(result.is_err());
    }

    #[test]
    fn is_able_to_detect_ipv4() {
        let ip = "127.0.0.1";
        let result = parse(ip).unwrap();

        match result {
            HostInfo::Ip { ip: parsed_ip } => {
                assert_eq!(parsed_ip, ip);
            }
            _ => panic!("Expected Ip variant"),
        }
    }

    #[test]
    fn wrong_ipv4_is_not_detected_as_ip() {
        let ip = "300.400.500.1";
        let result = parse(ip);

        assert!(result.is_err());
    }

    #[test]
    fn is_able_to_detect_tld_correctly() {
        let url = "example.com";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host {
                subdomain, domain, tld, ..
            } => {
                assert_eq!(subdomain, None);
                assert_eq!(domain, "example".to_string());
                assert_eq!(tld, Some("com".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn is_able_to_handle_fqdn() {
        let url = "subdomain.domain.com.";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host {
                subdomain, domain, tld, ..
            } => {
                assert_eq!(subdomain, Some("subdomain".to_string()));
                assert_eq!(domain, "domain".to_string());
                assert_eq!(tld, Some("com".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn is_able_to_parse_domain_with_same_subdomain_as_tld() {
        let url = "com.domain.com";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host {
                subdomain, domain, tld, ..
            } => {
                assert_eq!(subdomain, Some("com".to_string()));
                assert_eq!(domain, "domain".to_string());
                assert_eq!(tld, Some("com".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn is_able_to_parse_domain_with_same_subdomain_and_domain_as_tld() {
        let url = "com.com.com";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host {
                subdomain, domain, tld, ..
            } => {
                assert_eq!(subdomain, Some("com".to_string()));
                assert_eq!(domain, "com".to_string());
                assert_eq!(tld, Some("com".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }

    #[test]
    fn is_able_to_get_subdomain_domain_tld_with_multi_level_tld() {
        let url = "a.sub.domain.domain.co.uk";
        let result = parse(url).unwrap();

        match result {
            HostInfo::Host {
                subdomain, domain, tld, ..
            } => {
                assert_eq!(subdomain, Some("a.sub.domain".to_string()));
                assert_eq!(domain, "domain".to_string());
                assert_eq!(tld, Some("co.uk".to_string()));
            }
            _ => panic!("Expected Host variant"),
        }
    }
}
