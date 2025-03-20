use reqwest::Client;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use tokio::{fs as tokio_fs};
use tokio::sync::Semaphore;
use tokio_stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

const STANDARD_SERVICES: &[&str] = &[
    "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://DOMAIN&size=256",
    "https://icons.duckduckgo.com/ip3/DOMAIN.ico",
    "https://logo.clearbit.com/DOMAIN?size=64",
    "https://www.DOMAIN/favicon.ico",
    "https://DOMAIN/favicon.ico",
    "https://www.google.com/s2/favicons?domain=DOMAIN&sz=256",
];

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
            output_file: "issuerInfos".to_string(),
            domains_file: "domains.txt".to_string(),
            max_parallel: 50,
            timeout_secs: 5,
        }
    }
}

fn extract_name(domain: &str) -> String {
    domain.split('.').next().unwrap_or(domain).to_string()
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
        .filter_map(Result::ok)
        .filter(|d| !d.trim().is_empty())
        .collect();

    Ok(domains)
}

use tokio::time::{timeout, Duration};

async fn favicon_exists(client: &Client, config: &Config, url: &str) -> bool {
    let timeout_duration = Duration::from_secs(config.timeout_secs);

    // First, try HEAD
    if let Ok(Ok(resp)) = timeout(timeout_duration, client.head(url).send()).await {
        if resp.status().is_success() {
            return true;
        }
    }

    // Fallback to GET with content-type check
    if let Ok(Ok(resp)) = timeout(timeout_duration, client.get(url).send()).await {
        if resp.status().is_success() {
            if let Some(content_type) = resp.headers().get("content-type") {
                if content_type.to_str().unwrap_or("").starts_with("image") {
                    return true;
                }
            }
        }
    }

    false
}

async fn find_first_favicon(client: Arc<Client>, config: &Config, domain: String) -> Option<String> {
    let name = extract_name(&domain);
    let urls = build_favicon_urls(&domain);

    for url in urls {
        if favicon_exists(&client, &config, &url).await {
            return Some(format!("{};{};{}", name, domain, url));
        }
    }

    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Load configuration
    let config = match tokio_fs::read_to_string("config.toml").await {
        Ok(content) => toml::from_str(&content).unwrap_or_else(|_| {
            eprintln!("Invalid config file, using defaults");
            Config::default()
        }),
        Err(_) => {
            let default_config = Config::default();
            let toml = toml::to_string(&default_config).unwrap();
            tokio_fs::write("config.toml", toml).await.expect("Failed to create default config");
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
    pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} domains ({eta})")
            .unwrap()
            .progress_chars("=>-"));

    let client = Arc::new(Client::builder().user_agent("favicon-checker").build()?);
    let semaphore = Arc::new(Semaphore::new(config.max_parallel)); 

    let mut tasks = futures::stream::FuturesUnordered::new();

    for domain in domains {
        let client = Arc::clone(&client);
        let permit = semaphore.clone().acquire_owned().await?;
        let pb = Arc::clone(&pb);
        let config = config.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let result = find_first_favicon(client, &config, domain).await;
            pb.inc(1);
            result
        }));
    }

      // Collect all successful results
      let mut results = Vec::new();
      while let Some(result) = tasks.next().await {
          if let Ok(Some(line)) = result {
              results.push(line);
          }
      }
  
      pb.finish_with_message("Favicon check complete.");
      // Sort alphabetically by name (first part of the line)
      results.sort_by(|a, b| a.split(';').next().cmp(&b.split(';').next()));
  
      let mut output = File::create(config.output_file)?;
      for line in results {
          writeln!(output, "{}", line)?;
      }
  
      println!("Async favicon check complete. Results written to favicons.txt.");

    Ok(())
}