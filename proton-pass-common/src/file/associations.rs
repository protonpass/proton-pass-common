use super::FileGroup;
use file_format::FileFormat;
use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    pub static ref FILE_GROUP_MAP: HashMap<String, FileGroup> = initialize_file_group_map();
}

macro_rules! file_group_map {
    ( $( $format:expr => $group:expr ),* $(,)? ) => {{
        let mut map = HashMap::new();
        $(
            map.insert($format.media_type().to_string(), $group);
        )*
        map
    }};
}

fn initialize_file_group_map() -> HashMap<String, FileGroup> {
    file_group_map!(
        // Audio
        FileFormat::AdvancedAudioCoding => FileGroup::Audio,
        FileFormat::AppleItunesAudio => FileGroup::Audio,
        FileFormat::AppleItunesAudiobook => FileGroup::Audio,
        FileFormat::AppleItunesProtectedAudio => FileGroup::Audio,
        FileFormat::Au => FileGroup::Audio,
        FileFormat::AudioCodec3 => FileGroup::Audio,
        FileFormat::AudioInterchangeFileFormat => FileGroup::Audio,
        FileFormat::FreeLosslessAudioCodec => FileGroup::Audio,
        FileFormat::MatroskaAudio => FileGroup::Audio,
        FileFormat::Mpeg12AudioLayer2 => FileGroup::Audio,
        FileFormat::Mpeg12AudioLayer3 => FileGroup::Audio,
        FileFormat::Mpeg4Part14Audio => FileGroup::Audio,
        FileFormat::MusicalInstrumentDigitalInterface => FileGroup::Audio,
        FileFormat::OggFlac => FileGroup::Audio,
        FileFormat::OggOpus => FileGroup::Audio,
        FileFormat::OggSpeex => FileGroup::Audio,
        FileFormat::OggVorbis => FileGroup::Audio,
        FileFormat::WaveformAudio => FileGroup::Audio,
        FileFormat::Wavpack => FileGroup::Audio,
        FileFormat::WindowsMediaAudio => FileGroup::Audio,

        // Photo
        FileFormat::HighEfficiencyImageCoding => FileGroup::Photo,
        FileFormat::HighEfficiencyImageCodingSequence => FileGroup::Photo,
        FileFormat::HighEfficiencyImageFileFormat => FileGroup::Photo,
        FileFormat::HighEfficiencyImageFileFormatSequence => FileGroup::Photo,
        FileFormat::JointPhotographicExpertsGroup => FileGroup::Photo,
        FileFormat::Jpeg2000Codestream => FileGroup::Photo,
        FileFormat::Jpeg2000Part1 => FileGroup::Photo,
        FileFormat::Jpeg2000Part2 => FileGroup::Photo,
        FileFormat::Jpeg2000Part6 => FileGroup::Photo,
        FileFormat::JpegExtendedRange => FileGroup::Photo,
        FileFormat::JpegLs => FileGroup::Photo,
        FileFormat::JpegNetworkGraphics => FileGroup::Photo,
        FileFormat::JpegXl => FileGroup::Photo,

        // Image
        FileFormat::AdobePhotoshopDocument => FileGroup::Image,
        FileFormat::PortableNetworkGraphics => FileGroup::Image,
        FileFormat::PortableFloatmap => FileGroup::Image,
        FileFormat::PortableGraymap => FileGroup::Image,
        FileFormat::PortablePixmap => FileGroup::Image,
        FileFormat::TagImageFileFormat => FileGroup::Image,
        FileFormat::Webp => FileGroup::Image,
        FileFormat::WindowsBitmap => FileGroup::Image,
        FileFormat::WindowsIcon => FileGroup::Image,

        // Video
        FileFormat::ActionsMediaVideo => FileGroup::Video,
        FileFormat::AppleItunesVideo => FileGroup::Video,
        FileFormat::AppleQuicktime => FileGroup::Video,
        FileFormat::AudioVideoInterleave => FileGroup::Video,
        FileFormat::BdavMpeg2TransportStream => FileGroup::Video,
        FileFormat::FlashVideo => FileGroup::Video,
        FileFormat::Jpeg2000Part3 => FileGroup::Video,
        FileFormat::MaterialExchangeFormat => FileGroup::Video,
        FileFormat::Matroska3dVideo => FileGroup::Video,
        FileFormat::MatroskaVideo => FileGroup::Video,
        FileFormat::Mpeg12Video => FileGroup::Video,
        FileFormat::Mpeg2TransportStream => FileGroup::Video,
        FileFormat::Mpeg4Part14Video => FileGroup::Video,
        FileFormat::OggMedia => FileGroup::Video,
        FileFormat::OggTheora => FileGroup::Video,
        FileFormat::WindowsMediaVideo => FileGroup::Video,

        // VectorImage
        FileFormat::ScalableVectorGraphics => FileGroup::VectorImage,

        // Calendar
        FileFormat::Icalendar => FileGroup::Calendar,
        FileFormat::Vcalendar => FileGroup::Calendar,

        // Office
        FileFormat::MicrosoftWordDocument => FileGroup::Word,
        FileFormat::OfficeOpenXmlDocument => FileGroup::Word,
        FileFormat::MicrosoftExcelSpreadsheet => FileGroup::Excel,
        FileFormat::OfficeOpenXmlSpreadsheet => FileGroup::Excel,
        FileFormat::MicrosoftPowerpointPresentation => FileGroup::PowerPoint,
        FileFormat::OfficeOpenXmlPresentation => FileGroup::PowerPoint,

        // Documents
        FileFormat::PortableDocumentFormat => FileGroup::Pdf,
        FileFormat::RichTextFormat => FileGroup::Document,

        // Keys
        FileFormat::PgpPrivateKeyBlock => FileGroup::Key,
        FileFormat::PgpPublicKeyBlock => FileGroup::Key,

        // Text
        FileFormat::PlainText => FileGroup::Text,

    )
}
