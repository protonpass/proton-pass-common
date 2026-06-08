/*
 *  Copyright (c) 2026 Proton AG
 *  This file is part of Proton AG and Proton Pass.
 *
 *  Proton Pass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Proton Pass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Proton Pass.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

use std::path::{Path, PathBuf};

fn main() {
    generate_protos();
}

fn generate_protos() {
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("protos");

    let files = vec![("item_v1.proto", "item"), ("file_v1.proto", "file")];

    let mut mod_file_content = String::new();
    for (proto_file, mod_name) in files {
        generate_proto(proto_file, out_dir.join(mod_name));
        mod_file_content.push_str(&format!("pub mod {mod_name};\n"));
    }

    let mod_file_name = out_dir.join("mod.rs");
    std::fs::write(mod_file_name, mod_file_content).expect("Couldn't write mod file");
}

fn generate_proto(filename: &str, out_dir: PathBuf) {
    println!("cargo:rerun-if-changed=proto/{filename}");
    let proto_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("proto");
    let proto_path = proto_dir.join(filename);
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
