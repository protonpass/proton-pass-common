use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::env;

pub struct TwofaDomainCheck {
    set: HashSet<String>,
}

impl TwofaDomainCheck {
       const DEFAULT_FILE_NAME: &'static str = "2faDomains.txt";

       pub fn new() -> io::Result<Self> {
           let mut default_path = env::current_dir()?;
           default_path.push(Self::DEFAULT_FILE_NAME);
   
           let file = File::open(default_path)?;
           let lines = BufReader::new(file).lines();
            let set: HashSet<String> = lines.flatten().collect();

           Ok(TwofaDomainCheck { set })
       }

    pub fn twofa_domain_eligible(&self, term: &str) -> bool {
        self.set.contains(term)
    }
}