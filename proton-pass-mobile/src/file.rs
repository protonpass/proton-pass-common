pub use proton_pass_common::file::FileGroup;
use proton_pass_common::file::{get_file_group_from_mime_type, get_mime_type_from_content};

pub struct FileDecoder;

impl FileDecoder {
    pub fn new() -> Self {
        Self
    }

    pub fn get_mimetype_from_content(&self, content: Vec<u8>) -> String {
        get_mime_type_from_content(&content)
    }

    pub fn get_filegroup_from_mimetype(&self, mimetype: String) -> FileGroup {
        get_file_group_from_mime_type(&mimetype)
    }
}
