use public_suffix::{EffectiveTLDProvider, DEFAULT_PROVIDER};
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
        if DOMAINS.contains(term) {
            true
        } else {
            match DEFAULT_PROVIDER.effective_tld_plus_one(term) {
                Ok(d) => DOMAINS.contains(d),
                Err(_) => false,
            }
        }
    }
}
