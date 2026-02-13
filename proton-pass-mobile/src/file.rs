use proton_pass_common::file::FileGroup as CommonFileGroup;
use proton_pass_common::file::{get_file_group_from_mime_type, get_mime_type_from_content, sanitize_name};

// START MAPPING TYPES

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FileGroup {
    Image,
    Photo,
    VectorImage,
    Video,
    Audio,
    Key,
    Text,
    Calendar,
    Pdf,
    Word,
    PowerPoint,
    Excel,
    Document,
    Unknown,
}

impl From<CommonFileGroup> for FileGroup {
    fn from(group: CommonFileGroup) -> Self {
        match group {
            CommonFileGroup::Image => FileGroup::Image,
            CommonFileGroup::Photo => FileGroup::Photo,
            CommonFileGroup::VectorImage => FileGroup::VectorImage,
            CommonFileGroup::Video => FileGroup::Video,
            CommonFileGroup::Audio => FileGroup::Audio,
            CommonFileGroup::Key => FileGroup::Key,
            CommonFileGroup::Text => FileGroup::Text,
            CommonFileGroup::Calendar => FileGroup::Calendar,
            CommonFileGroup::Pdf => FileGroup::Pdf,
            CommonFileGroup::Word => FileGroup::Word,
            CommonFileGroup::PowerPoint => FileGroup::PowerPoint,
            CommonFileGroup::Excel => FileGroup::Excel,
            CommonFileGroup::Document => FileGroup::Document,
            CommonFileGroup::Unknown => FileGroup::Unknown,
        }
    }
}

// END MAPPING TYPES

#[derive(uniffi::Object)]
pub struct FileDecoder;

#[uniffi::export]
impl FileDecoder {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn get_mimetype_from_content(&self, content: Vec<u8>) -> String {
        get_mime_type_from_content(&content)
    }

    pub fn get_filegroup_from_mimetype(&self, mimetype: String) -> FileGroup {
        FileGroup::from(get_file_group_from_mime_type(&mimetype))
    }

    pub fn sanitize_filename(&self, name: String, windows: bool) -> String {
        sanitize_name(&name, windows)
    }
}
