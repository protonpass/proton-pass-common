use proton_pass_common::file::get_mime_type_from_content;

macro_rules! mime_type_test {
    ($($name:ident: $value:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (path, expected) = $value;
            let crate_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            let file_path = crate_path.join("test_data").join(path);

            let contents = std::fs::read(&file_path).expect(&format!("cannot open {}", file_path.display()));

            let res = get_mime_type_from_content(&contents);
            assert_eq!(res, expected);
        }
    )*
    }
}

mime_type_test! {
    txt: ("sample.txt", "text/plain"),
    wav: ("sample.wav", "audio/vnd.wave"),
    jpg: ("sample.jpg", "image/jpeg"),
    png: ("sample.png", "image/png"),
    svg: ("sample.svg", "image/svg+xml"),
    unclosed_svg: ("sample-unclosed.svg", "image/svg+xml"),
    mp3: ("sample.mp3", "audio/mpeg"),
    pgp_public: ("pgpkey.pub", "application/pgp-keys"),
    pgp_private: ("pgpkey.private", "application/pgp-keys"),
    zip: ("sample.zip", "application/zip"),
    rar: ("sample.rar", "application/vnd.rar"),
    docx: ("sample.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    pdf: ("sample.pdf", "application/pdf"),
    xlsx: ("sample.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    garbage: ("sample.garbage", "application/octet-stream"),
    ics: ("sample.ics", "text/calendar"),
    mp4: ("sample.mp4", "video/mp4"),
    avi: ("sample.avi", "video/avi"),
}
