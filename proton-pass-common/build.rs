use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// https://doc.rust-lang.org/cargo/reference/build-scripts.html#case-study-code-generation
fn main() {
    build_eff_wordlist();
    build_common_password_list();
    build_2fa_domains_list();
    generate_google_authenticator_proto();
}

fn build_eff_wordlist() {
    println!("cargo:rerun-if-changed=eff_words.txt");
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

fn generate_google_authenticator_proto() {
    println!("cargo:rerun-if-changed=proto/google_authenticator.proto");
    let proto_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("proto");
    let proto_path = proto_dir.join("google_authenticator.proto");
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("authenticator")
        .join("parser")
        .join("google")
        .join("gen");
    if !out_dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .create(&out_dir)
            .expect("error creating out dir");
    }

    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .include(proto_dir)
        .input(proto_path)
        .out_dir(out_dir)
        .run()
        .expect("failed to generate rust from proto");
}
