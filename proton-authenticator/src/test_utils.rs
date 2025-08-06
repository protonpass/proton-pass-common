use crate::log::{LogLevel, Logger};

pub fn get_file_contents_raw(name: &str) -> Vec<u8> {
    let crate_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let file_path = crate_path.join("test_data").join("authenticator").join(name);

    std::fs::read(&file_path).unwrap_or_else(|_| panic!("cannot open {}", file_path.display()))
}

pub fn get_file_contents(name: &str) -> String {
    String::from_utf8(get_file_contents_raw(name)).unwrap_or_else(|e| panic!("cannot read {name}: {e:?}"))
}

pub struct TestLogger;

impl Logger for TestLogger {
    fn log(&self, level: LogLevel, msg: String) {
        eprintln!("[{level:?}] {msg}");
    }
}

#[macro_export]
macro_rules! setup_test_logs {
    () => {
        $crate::log::register_authenticator_logger(std::sync::Arc::new($crate::test_utils::TestLogger));
    };
}
