use file_format::FileFormat;

mod associations;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
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

pub fn get_mime_type_from_content(input: &[u8]) -> String {
    let format = FileFormat::from_bytes(input);
    format.media_type().to_string()
}

pub fn get_file_group_from_mime_type(mime_type: &str) -> FileGroup {
    let as_lower = mime_type.to_lowercase();
    let decoded = associations::FILE_GROUP_MAP
        .get(&as_lower)
        .cloned()
        .unwrap_or(FileGroup::Unknown);

    if FileGroup::Unknown == decoded {
        get_file_group_from_heuristics(&as_lower)
    } else {
        decoded
    }
}

fn get_file_group_from_heuristics(mime_type: &str) -> FileGroup {
    let first_part = mime_type.split('/').next().unwrap_or("");
    match first_part {
        "image" => FileGroup::Image,
        "video" => FileGroup::Video,
        "audio" => FileGroup::Audio,
        "text" => FileGroup::Text,
        _ => FileGroup::Unknown,
    }
}
