use crate::parser::ImportError;

pub fn validate_digits(digits: u32, entry_name: &str) -> Option<String> {
    if !(1..=9).contains(&digits) {
        Some(format!(
            "Invalid entry digits for {} (must be between 1-9 and got {})",
            entry_name, digits
        ))
    } else {
        None
    }
}

pub fn validate_period(period: u32, entry_name: &str) -> Option<String> {
    if period < 1 {
        Some(format!("Invalid entry period for {}", entry_name))
    } else {
        None
    }
}

pub fn validate_totp_parameters(digits: u32, period: u32, entry_name: &str) -> Vec<ImportError> {
    let mut errors = Vec::new();

    if let Some(digits_error) = validate_digits(digits, entry_name) {
        errors.push(ImportError {
            context: entry_name.to_string(),
            message: digits_error,
        });
    }

    if let Some(period_error) = validate_period(period, entry_name) {
        errors.push(ImportError {
            context: entry_name.to_string(),
            message: period_error,
        });
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_digits_valid() {
        assert!(validate_digits(1, "test").is_none());
        assert!(validate_digits(6, "test").is_none());
        assert!(validate_digits(9, "test").is_none());
    }

    #[test]
    fn test_validate_digits_invalid_zero() {
        let error = validate_digits(0, "bad-entry");
        assert!(error.is_some());
        assert!(error.unwrap().contains("digits"));
    }

    #[test]
    fn test_validate_digits_invalid_high() {
        let error = validate_digits(10, "bad-entry");
        assert!(error.is_some());
        assert!(error.unwrap().contains("digits"));
    }

    #[test]
    fn test_validate_digits_truncation_prevention() {
        // Test that large values that would truncate are caught
        let error = validate_digits(262, "bad-entry"); // 262 as u8 wraps to 6
        assert!(error.is_some());
        assert!(error.unwrap().contains("digits"));
    }

    #[test]
    fn test_validate_period_valid() {
        assert!(validate_period(1, "test").is_none());
        assert!(validate_period(30, "test").is_none());
        assert!(validate_period(60, "test").is_none());
    }

    #[test]
    fn test_validate_period_invalid_zero() {
        let error = validate_period(0, "bad-entry");
        assert!(error.is_some());
        assert!(error.unwrap().contains("period"));
    }

    #[test]
    fn test_validate_totp_parameters_valid() {
        let errors = validate_totp_parameters(6, 30, "valid-entry");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_totp_parameters_both_invalid() {
        let errors = validate_totp_parameters(0, 0, "bad-entry");
        assert_eq!(errors.len(), 2);
        assert!(errors[0].message.contains("digits"));
        assert!(errors[1].message.contains("period"));
    }

    #[test]
    fn test_validate_totp_parameters_digits_only_invalid() {
        let errors = validate_totp_parameters(0, 30, "bad-entry");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("digits"));
    }

    #[test]
    fn test_validate_totp_parameters_period_only_invalid() {
        let errors = validate_totp_parameters(6, 0, "bad-entry");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("period"));
    }
}
