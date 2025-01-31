use std::path::{Path, PathBuf};

fn main() {
    generate_protos();
}

fn generate_protos() {
    generate_google_authenticator_proto();
    generate_authenticator_entry_proto();
}

fn generate_google_authenticator_proto() {
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("parser")
        .join("google")
        .join("gen");
    generate_proto("google_authenticator.proto", out_dir)
}

fn generate_authenticator_entry_proto() {
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("entry")
        .join("gen");
    generate_proto("authenticator_entry.proto", out_dir)
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
