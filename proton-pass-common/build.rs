use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// https://doc.rust-lang.org/cargo/reference/build-scripts.html#case-study-code-generation
fn main() {
    build_eff_wordlist();
    build_common_password_list();
    build_2fa_domains_lsit();
}

fn build_eff_wordlist() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("wordlists.rs");
    let f = File::create(dest_path).expect("Could not create wordlists.rs");
    eff_wordlist(&f, "EFF_LARGE_WORDLIST", "eff_large_wordlist.txt");
}

fn build_common_password_list() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("common_passwords.rs");
    let f = File::create(dest_path).expect("Could not create common_passwords.rs");
    common_passwords(&f, "COMMON_PASSWORDS", "passwords.txt");
}

fn build_2fa_domains_lsit() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("twofaDomains.rs");
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

fn eff_wordlist(mut f_dest: &File, const_name: &str, fname_src: &str) {
    f_dest.write_all(b"const ").expect("Error writing wordlist");
    f_dest.write_all(const_name.as_bytes()).expect("Error writing wordlist");
    f_dest.write_all(b": &[&str] = &[").expect("Error writing wordlist");

    let f_src = BufReader::new(File::open(fname_src).unwrap_or_else(|e| panic!("Error opening {fname_src}: {e}")));
    for (line_number, line) in f_src.lines().enumerate() {
        f_dest.write_all(b"\"").expect("Error writing wordlist");

        let wordlist_line = line.expect("Error reading line from wordlist");
        let word = wordlist_line
            .split('\t')
            .nth(1)
            .unwrap_or_else(|| panic!("Malformed line in wordlist (line {line_number})"));
        f_dest.write_all(word.as_bytes()).expect("Error writing wordlist");
        f_dest.write_all(b"\",").expect("Error writing wordlist");
    }

    f_dest.write_all(b"];").expect("Error writing wordlist");
}
