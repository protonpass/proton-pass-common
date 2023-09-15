use proton_pass_common::*;

#[test]
fn without_at() {
    assert!(!is_email_valid("test.com"))
}
