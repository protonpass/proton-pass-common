use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// https://doc.rust-lang.org/cargo/reference/build-scripts.html#case-study-code-generation
fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("wordlists.rs");
    let f = File::create(dest_path).expect("Could not create wordlists.rs");
    words(&f, "EFF_LARGE_WORDLIST", "eff_large_wordlist.txt");
}

fn words(mut f_dest: &File, const_name: &str, fname_src: &str) {
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
