use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::ops::Add;

fn main() {
    merge_udl_files();
    uniffi::generate_scaffolding("src/common.udl").unwrap();
}

fn merge_udl_files() {
    let common_udl_file = File::create("src/common.udl").expect("Could not create common.udl");

    let all_udl_file_names = ["base", "alias", "email", "login", "password", "totp"];

    for name in all_udl_file_names {
        merge(format!("src/{}.udl", name), &common_udl_file);
    }
}

fn merge(src_udl_path: String, mut file: &File) {
    let content = get_string_from_file_path(&src_udl_path)
        .unwrap_or_else(|_| panic!("Fail to read the content of {}", src_udl_path))
        .add("\n\n");
    file.write_all(content.as_bytes())
        .unwrap_or_else(|_| panic!("Error copying from {}", src_udl_path));
}
fn get_string_from_file_path(path: &str) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}
