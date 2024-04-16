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
            match crate::domain::get_root_domain(term) {
                Ok(domain) => match DEFAULT_PROVIDER.effective_tld_plus_one(&domain) {
                    Ok(d) => DOMAINS.contains(d),
                    Err(_) => false,
                },
                Err(_) => false,
            }
        }
    }
}
