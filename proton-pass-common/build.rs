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

fn build_username_wordlists() {
    println!("cargo:rerun-if-changed=username_wordlists/adjectives.txt");
    println!("cargo:rerun-if-changed=username_wordlists/verbs.txt");
    println!("cargo:rerun-if-changed=username_wordlists/nouns.txt");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("username_wordlists.rs");
    let f = File::create(dest_path).expect("Could not create username_wordlist.rs");
    write_wordlist(&f, "ADJECTIVES_LIST", "username_wordlists/adjectives.txt");
    write_wordlist(&f, "NOUNS_LIST", "username_wordlists/nouns.txt");
    write_wordlist(&f, "VERBS_LIST", "username_wordlists/verbs.txt");
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

fn write_str_array(mut dst: &File, const_name: &str, entries: impl Iterator<Item = String>) {
    writeln!(dst, "const {const_name}: &[&str] = &[").expect("Error writing string array");
    for entry in entries {
        writeln!(dst, "{entry:?},").expect("Error writing string array");
    }
    dst.write_all(b"];\n\n").expect("Error writing string array");
}

fn domain_2fa(dst: &File, const_name: &str, filename: &str) {
    let src = BufReader::new(File::open(filename).unwrap_or_else(|e| panic!("Error opening {filename}: {e}")));
    let entries = src.lines().map(|line| line.expect("Error reading line from file"));
    write_str_array(dst, const_name, entries);
}

fn common_passwords(dst: &File, const_name: &str, filename: &str) {
    let src = BufReader::new(File::open(filename).unwrap_or_else(|e| panic!("Error opening {filename}: {e}")));
    let entries = src.lines().map(|line| line.expect("Error reading line from file"));
    write_str_array(dst, const_name, entries);
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

fn write_wordlist(f: &File, const_name: &str, filepath: &str) {
    let file = File::open(filepath).unwrap_or_else(|e| panic!("Error opening {filepath}: {e}"));
    let reader = BufReader::new(file);

    let entries = reader
        .lines()
        .map(|line| line.expect("Error reading line"))
        .map(|line| line.trim().to_string())
        .filter(|word| !word.is_empty() && !word.starts_with('#'));

    write_str_array(f, const_name, entries);
}

fn eff_wordlist(f_dest: &File, const_name: &str, fname_src: &str) {
    let denylist = load_denylist();
    let f_src = BufReader::new(File::open(fname_src).unwrap_or_else(|e| panic!("Error opening {fname_src}: {e}")));

    let mut word_count = 0;
    let mut filtered_count = 0;
    let mut entries = Vec::new();
    for (line_number, line) in f_src.lines().enumerate() {
        let wordlist_line = line.expect("Error reading line from wordlist");
        let word = wordlist_line
            .split('\t')
            .nth(1)
            .unwrap_or_else(|| panic!("Malformed line in wordlist (line {line_number})"));

        // Check if word is in denylist (case-insensitive)
        if !denylist.contains(&word.to_lowercase()) {
            entries.push(word.to_string());
            word_count += 1;
        } else {
            filtered_count += 1;
        }
    }

    write_str_array(f_dest, const_name, entries.into_iter());
    println!("cargo:warning=Generated wordlist with {word_count} words ({filtered_count} words filtered out)");
}
