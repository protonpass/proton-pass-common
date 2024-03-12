use std::collections::HashSet;
use std::env;

include!(concat!(env!("OUT_DIR"), "/twofa_domains.rs"));

lazy_static::lazy_static! {
    static ref DOMAINS: HashSet<String> = {
        let mut set = HashSet::new();
        TWOFA_DOMAINS.iter().for_each(|s| {
            set.insert(s.to_string());
        });
        set
    };
}

pub struct TwofaDomainChecker;

impl TwofaDomainChecker {
    pub fn twofa_domain_eligible(term: &str) -> bool {
        DOMAINS.contains(term)
    }
}
