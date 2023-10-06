use std::fs::File;
use std::io::{Read, Write};
use std::ops::Add;
use std::{fs, io};

type IOError = io::Error;
pub const OUTPUT_UDL_NAME: &str = "common";

fn main() {
    println!("cargo:rerun-if-changed=src/*.udl");

    merge_udl_files();
    uniffi::generate_scaffolding(format!("src/{}.udl", OUTPUT_UDL_NAME)).unwrap();
}

fn merge_udl_files() {
    let path = format!("src/{}.udl", OUTPUT_UDL_NAME);
    let mut file = File::create(&path).unwrap_or_else(|_| panic!("Could not create {}", path));

    let header_comment = r#"// This file is auto-generated and contains the concatenated contents of all the UDL files in src directory
// Do not edit this manually but instead editing/adding UDL files in the src directory

"#;

    file.write_all(header_comment.as_bytes())
        .unwrap_or_else(|_| panic!("Error writing to {path}"));

    let other_udl_file_paths = scan_udl_files().unwrap_or_else(|_| panic!("Can not scan src directory"));

    for path in other_udl_file_paths {
        merge(path, &file);
    }
}

// Get all the UDL files excluding OUTPUT_UDL_NAME in src directory
fn scan_udl_files() -> Result<Vec<String>, IOError> {
    let files = fs::read_dir("src")?;
    let udl_files: Vec<_> = files
        .filter_map(|file| {
            let file = file.ok()?;
            let path = file.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "udl") {
                match path.file_name() {
                    Some(file_name) => match file_name.to_str() {
                        Some(value) => {
                            if value == format!("{}.udl", OUTPUT_UDL_NAME) {
                                None
                            } else {
                                Some(format!("src/{}", value))
                            }
                        }
                        None => None,
                    },
                    None => None,
                }
            } else {
                None
            }
        })
        .collect();

    Ok(udl_files)
}

fn merge(src_udl_path: String, mut file: &File) {
    let content = get_string_from_file_path(&src_udl_path)
        .unwrap_or_else(|_| panic!("Fail to read the content of {}", src_udl_path))
        .add("\n\n");
    file.write_all(content.as_bytes())
        .unwrap_or_else(|_| panic!("Error copying from {}", src_udl_path));
}

fn get_string_from_file_path(path: &str) -> Result<String, IOError> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}
