use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// https://doc.rust-lang.org/cargo/reference/build-scripts.html#case-study-code-generation
fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("wordlists.rs");
    let f = File::create(dest_path).unwrap();
    words(&f, "EFF_LARGE_WORDLIST", "eff_large_wordlist.txt");
}

fn words(mut f_dest: &File, const_name: &str, fname_src: &str) {
    f_dest.write_all(b"const ").unwrap();
    f_dest.write_all(const_name.as_bytes()).unwrap();
    f_dest.write_all(b": &[&str] = &[").unwrap();

    let f_src = BufReader::new(File::open(fname_src).unwrap());
    for line in f_src.lines() {
        f_dest.write_all(b"\"").unwrap();

        f_dest
            .write_all(line.unwrap().split('\t').nth(1).unwrap().as_bytes())
            .unwrap();

        f_dest.write_all(b"\",").unwrap();
    }

    f_dest.write_all(b"];").unwrap();
}
