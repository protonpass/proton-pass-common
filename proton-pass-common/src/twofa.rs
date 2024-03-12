use std::collections::HashSet;
use std::env;
// use std::io::{self, BufRead, BufReader};

pub struct TwofaDomainChecker {
    set: HashSet<String>,
}

include!(concat!(env!("OUT_DIR"), "/twofaDomains.rs"));

impl Default for TwofaDomainChecker {
    fn default() -> Self {
        Self {
            set: TWOFA_DOMAINS.iter().map(|&s| s.to_string()).collect(),
        }
    }
}

impl TwofaDomainChecker {
    pub fn twofa_domain_eligible(&self, term: &str) -> bool {
        self.set.contains(term)
    }
}
