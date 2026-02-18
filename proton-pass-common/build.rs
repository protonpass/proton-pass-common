use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// https://doc.rust-lang.org/cargo/reference/build-scripts.html#case-study-code-generation
fn main() {
    build_eff_wordlist();
    build_common_password_list();
    build_2fa_domains_list();
    build_username_wordlists();
}

fn build_username_wordlists(){
    println!("cargo:rerun-if-changed=username_wordlists/adjectives.txt");
    println!("cargo:rerun-if-changed=username_wordlists/verbs.txt");
    println!("cargo:rerun-if-changed=username_wordlists/nouns.txt");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("username_wordlists.rs");
    let mut f = File::create(dest_path).expect("Could not create username_wordlist.rs");
    write_wordlist(&mut f, "ADJECTIVES_LIST", "username_wordlists/adjectives.txt");
    write_wordlist(&mut f, "NOUNS_LIST", "username_wordlists/nouns.txt");
    write_wordlist(&mut f, "VERBS_LIST", "username_wordlists/verbs.txt");    
}

fn build_eff_wordlist() {
    println!("cargo:rerun-if-changed=eff_large_wordlist.txt");
    println!("cargo:rerun-if-changed=wordlist_denylist.txt");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("wordlists.rs");
    let f = File::create(dest_path).expect("Could not create wordlists.rs");
    eff_wordlist(&f, "EFF_LARGE_WORDLIST", "eff_large_wordlist.txt");
}

fn build_common_password_list() {
    println!("cargo:rerun-if-changed=passwords.txt");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("common_passwords.rs");
    let f = File::create(dest_path).expect("Could not create common_passwords.rs");
    common_passwords(&f, "COMMON_PASSWORDS", "passwords.txt");
}

fn build_2fa_domains_list() {
    println!("cargo:rerun-if-changed=2faDomains.txt");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("twofa_domains.rs");
    let f = File::create(dest_path).expect("Could not create twofaDomains.rs");
    domain_2fa(&f, "TWOFA_DOMAINS", "2faDomains.txt");
}

fn domain_2fa(mut dst: &File, const_name: &str, filename: &str) {
    dst.write_all(b"const ").expect("Error writing common 2fa domain list");
    dst.write_all(const_name.as_bytes())
        .expect("Error writing common 2fa domain list");
    dst.write_all(b": &[&str] = &[")
        .expect("Error writing common 2fa domain list");

    let src = BufReader::new(File::open(filename).unwrap_or_else(|e| panic!("Error opening {filename}: {e}")));

    for line in src.lines() {
        let password = line.expect("Error reading line from file");
        dst.write_all(b"\"").expect("Error writing common 2fa domain");
        dst.write_all(password.as_bytes())
            .expect("Error writing common 2fa domain");
        dst.write_all(b"\",").expect("Error writing common 2fa domain");
    }

    dst.write_all(b"];").expect("Error writing common 2fa domain");
}

fn common_passwords(mut dst: &File, const_name: &str, filename: &str) {
    dst.write_all(b"const ").expect("Error writing common password list");
    dst.write_all(const_name.as_bytes())
        .expect("Error writing common password list");
    dst.write_all(b": &[&str] = &[")
        .expect("Error writing common password list");

    let src = BufReader::new(File::open(filename).unwrap_or_else(|e| panic!("Error opening {filename}: {e}")));

    for line in src.lines() {
        let password = line.expect("Error reading line from file");
        dst.write_all(b"\"").expect("Error writing common password");
        dst.write_all(password.as_bytes())
            .expect("Error writing common password");
        dst.write_all(b"\",").expect("Error writing common password");
    }

    dst.write_all(b"];").expect("Error writing common password");
}

fn load_denylist() -> HashSet<String> {
    let mut denylist = HashSet::new();

    if let Ok(file) = File::open("wordlist_denylist.txt") {
        let reader = BufReader::new(file);
        for word in reader.lines().map_while(Result::ok) {
            let trimmed = word.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                denylist.insert(trimmed.to_lowercase());
            }
        }
    }

    denylist
}

fn write_wordlist(f: &mut File, const_name: &str, filepath: &str) {
      f.write_all(b"const ").expect("Error writing wordlist");
      f.write_all(const_name.as_bytes()).expect("Error writing wordlist");
      f.write_all(b": &[&str] = &[").expect("Error writing wordlist");

      let file = File::open(filepath).unwrap_or_else(|e| panic!("Error opening {filepath}: {e}"));
      let reader = BufReader::new(file);

      for line in reader.lines() {
          let word = line.expect("Error reading line");
          let word = word.trim();
          if !word.is_empty() && !word.starts_with('#') {
              f.write_all(b"\"").expect("Error writing word");
              f.write_all(word.as_bytes()).expect("Error writing word");
              f.write_all(b"\",").expect("Error writing word");
          }
      }

      f.write_all(b"];\n\n").expect("Error writing wordlist");
  }

fn eff_wordlist(mut f_dest: &File, const_name: &str, fname_src: &str) {
    f_dest.write_all(b"const ").expect("Error writing wordlist");
    f_dest.write_all(const_name.as_bytes()).expect("Error writing wordlist");
    f_dest.write_all(b": &[&str] = &[").expect("Error writing wordlist");

    let denylist = load_denylist();
    let f_src = BufReader::new(File::open(fname_src).unwrap_or_else(|e| panic!("Error opening {fname_src}: {e}")));

    let mut word_count = 0;
    let mut filtered_count = 0;
    for (line_number, line) in f_src.lines().enumerate() {
        let wordlist_line = line.expect("Error reading line from wordlist");
        let word = wordlist_line
            .split('\t')
            .nth(1)
            .unwrap_or_else(|| panic!("Malformed line in wordlist (line {line_number})"));

        // Check if word is in denylist (case-insensitive)
        if !denylist.contains(&word.to_lowercase()) {
            f_dest.write_all(b"\"").expect("Error writing wordlist");
            f_dest.write_all(word.as_bytes()).expect("Error writing wordlist");
            f_dest.write_all(b"\",").expect("Error writing wordlist");
            word_count += 1;
        } else {
            filtered_count += 1;
        }
    }

    f_dest.write_all(b"];").expect("Error writing wordlist");
    println!("cargo:warning=Generated wordlist with {word_count} words ({filtered_count} words filtered out)");
}
