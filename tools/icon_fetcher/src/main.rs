use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use tokio::fs as tokio_fs;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

const STANDARD_SERVICES: &[&str] = &[
    "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://DOMAIN&size=256",
    "https://icons.duckduckgo.com/ip3/DOMAIN.ico",
    "https://logo.clearbit.com/DOMAIN?size=64",
    "https://www.DOMAIN/favicon.ico",
    "https://DOMAIN/favicon.ico",
    "https://www.google.com/s2/favicons?domain=DOMAIN&sz=256",
];

struct FaviconInfo {
    pub name: String,
    pub domain: String,
    pub icon_url: String,
}

impl FaviconInfo {
    pub fn to_line(&self) -> String {
        format!("{};{};{}", self.name, self.domain, self.icon_url)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    output_file: String,
    domains_file: String,
    max_parallel: usize,
    timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output_file: "proton-authenticator/resources/issuerInfos.txt".to_string(),
            domains_file: "2faDomains.txt".to_string(),
            max_parallel: 50,
            timeout_secs: 5,
        }
    }
}

pub async fn fetch_public_suffixes(client: &Client, z: HashSet<String>) -> HashSet<String> {
    let url = "https://publicsuffix.org/list/public_suffix_list.dat";

    match client.get(url).send().await {
        Ok(response) => match response.text().await {
            Ok(body) => parse_public_suffix_list(&body).unwrap_or(z),
            Err(_) => z,
        },
        Err(_) => z,
    }
}

fn parse_public_suffix_list(body: &str) -> Option<HashSet<String>> {
    let mut suffixes = HashSet::new();
    let re = Regex::new(r"^(?P<suffix>[^/\n]+)").ok()?;

    for line in body.lines() {
        let line = line.trim();
        if line.starts_with("//") || line.is_empty() {
            continue;
        }

        if let Some(caps) = re.captures(line) {
            let suffix = caps["suffix"].trim().to_lowercase();
            if !suffix.is_empty() {
                suffixes.insert(suffix);
            }
        }
    }

    Some(suffixes)
}

fn extract_name(domain: &str, suffixes: &HashSet<String>) -> String {
    let domain = domain.to_lowercase();
    let parts: Vec<&str> = domain.split('.').collect();

    // Check for multi-level matches (e.g., .co.uk)
    for i in 1..parts.len() {
        let test_suffix = parts[i..].join(".");
        if suffixes.contains(&test_suffix) {
            return parts[..i].join(".");
        }
    }

    // Fallback to removing just the last part
    if parts.len() > 1 {
        parts[..parts.len() - 1].join(".")
    } else {
        domain
    }
}

fn build_favicon_urls(domain: &str) -> Vec<String> {
    STANDARD_SERVICES
        .iter()
        .map(|template| template.replace("DOMAIN", domain))
        .collect()
}

fn read_domains_from_file(path: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let domains: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|d| !d.trim().is_empty())
        .collect();

    Ok(domains)
}

async fn favicon_exists(client: &Client, config: &Config, url: &str) -> bool {
    let timeout_duration = Duration::from_secs(config.timeout_secs);

    match timeout(timeout_duration, client.head(url).send()).await {
        Ok(Ok(resp)) if resp.status().is_success() => return true,
        Ok(Ok(resp)) => {
            eprintln!("HEAD {} -> status {}", url, resp.status());
        }
        Ok(Err(err)) => {
            eprintln!("HEAD {} failed: {}", url, err);
        }
        Err(_) => {
            eprintln!("HEAD {} timed out after {}s", url, config.timeout_secs);
        }
    }

    match timeout(timeout_duration, client.get(url).send()).await {
        Ok(Ok(resp)) => {
            if resp.status().is_success() {
                if let Some(content_type) = resp.headers().get("content-type") {
                    let mime = content_type.to_str().unwrap_or("");
                    if mime.starts_with("image") {
                        return true;
                    } else {
                        eprintln!("GET {} -> unexpected content-type: {}", url, mime);
                    }
                } else {
                    eprintln!("GET {} succeeded, but no content-type header", url);
                }
            } else {
                eprintln!("GET {} -> status {}", url, resp.status());
            }
        }
        Ok(Err(err)) => {
            eprintln!("GET {} failed: {}", url, err);
        }
        Err(_) => {
            eprintln!("GET {} timed out after {}s", url, config.timeout_secs);
        }
    }

    false
}

async fn find_first_favicon(
    client: Arc<Client>,
    config: &Config,
    domain: String,
    suffixes: &HashSet<String>,
) -> Option<FaviconInfo> {
    let name = extract_name(&domain, suffixes);
    let urls = build_favicon_urls(&domain);

    for url in urls {
        if favicon_exists(&client, config, &url).await {
            return Some(FaviconInfo {
                domain,
                name,
                icon_url: url,
            });
        }
    }

    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <path to config file found in tool/icon_fetcher>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    let config = match tokio_fs::read_to_string(path).await {
        Ok(content) => toml::from_str(&content).unwrap_or_else(|_| {
            eprintln!("Invalid config file, using defaults");
            Config::default()
        }),
        Err(_) => {
            let default_config = Config::default();
            let toml = toml::to_string(&default_config).unwrap();
            tokio_fs::write("config.toml", toml)
                .await
                .expect("Failed to create default config");
            default_config
        }
    };

    // Read domains
    let domains = match read_domains_from_file(&config.domains_file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read domains: {}", e);
            std::process::exit(1);
        }
    };

    if domains.is_empty() {
        eprintln!("No domains found in {}", config.domains_file);
        std::process::exit(1);
    }

    let total = domains.len() as u64;
    let pb = Arc::new(ProgressBar::new(total));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} domains ({eta})")
            .unwrap()
            .progress_chars("=>-"),
    );

    let client = Arc::new(Client::builder().user_agent("favicon-checker").build()?);
    let semaphore = Arc::new(Semaphore::new(config.max_parallel));

    let mut tasks = Vec::new();

    // Fallback in case fetching fails
    let mut fallback = HashSet::new();
    fallback.insert("com".to_string());
    fallback.insert("net".to_string());
    fallback.insert("org".to_string());
    fallback.insert("co.uk".to_string());
    fallback.insert("com.au".to_string());
    fallback.insert("com.eu".to_string());

    let suffixes = fetch_public_suffixes(&client, fallback).await;
    let suffixes = Arc::new(suffixes);

    for domain in domains {
        let client = client.clone();
        let permit = semaphore.clone().acquire_owned(); //.await?;
        let pb = pb.clone();
        let config = config.clone();
        let suffixes = suffixes.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = match permit.await {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("Semaphore permit acquisition failed.");
                    return None;
                }
            };

            let result = find_first_favicon(client, &config, domain, &suffixes).await;
            pb.inc(1);
            result
        }));
    }

    let mut stream = tokio_stream::iter(tasks).buffer_unordered(config.max_parallel);

    // Collect all successful results
    let mut results = Vec::new();
    while let Some(result) = stream.next().await {
        match result {
            Ok(Some(line)) => results.push(line),
            Ok(None) => {} // favicon not found
            Err(e) => eprintln!("Task failed: {}", e),
        }
    }

    pb.finish_with_message("Favicon check complete.");
    // Sort alphabetically by name (first part of the line)
    results.sort_by(|a, b| a.name.cmp(&b.name));

    let mut output = File::create(config.output_file)?;
    for line in results {
        writeln!(output, "{}", line.to_line())?;
    }

    println!("Async favicon check complete. Results written to favicons.txt.");

    Ok(())
}
