use proton_pass_common::email;

#[test]
fn without_at() {
    assert!(!email::is_email_valid("test.com"))
}
