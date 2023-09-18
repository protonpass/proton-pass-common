use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum AliasPrefixError {
    TwoConsecutiveDots,
    InvalidCharacter,
    DotAtTheEnd,
    PrefixTooLong,
    PrefixEmpty,
}
impl std::error::Error for AliasPrefixError {}
impl fmt::Display for AliasPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub const MAX_PREFIX_LENGTH: usize = 40;

pub fn validate_alias_prefix(prefix: &str) -> Result<(), AliasPrefixError> {
    if prefix.is_empty() {
        return Err(AliasPrefixError::PrefixEmpty);
    }

    if prefix.len() >= MAX_PREFIX_LENGTH {
        return Err(AliasPrefixError::PrefixTooLong);
    }

    if prefix.contains("..") {
        return Err(AliasPrefixError::TwoConsecutiveDots);
    }

    if prefix.ends_with('.') {
        return Err(AliasPrefixError::DotAtTheEnd);
    }

    let valid_characters = [
        '_', '-', '.', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
        't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];

    if !prefix.chars().all(|c| valid_characters.contains(&c)) {
        Err(AliasPrefixError::InvalidCharacter)
    } else {
        Ok(())
    }
}
