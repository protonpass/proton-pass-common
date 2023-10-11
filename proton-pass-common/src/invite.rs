pub fn create_signature_body(email: &str, vault_key: Vec<u8>) -> Vec<u8> {
    let mut res = Vec::new();

    let email_as_bytes = email.as_bytes().to_vec();
    res.extend(&email_as_bytes);
    res.push(b'|');
    res.extend(&vault_key);

    res
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn happy_path() {
        let res = create_signature_body("test", vec![0x12, 0x34, 0x56]);
        assert_eq!(vec![b't', b'e', b's', b't', b'|', 0x12, 0x34, 0x56], res);
    }

    #[test]
    fn empty_email() {
        let vault_key = 0x12;
        let res = create_signature_body("", vec![vault_key]);
        assert_eq!(vec![b'|', vault_key], res);
    }

    #[test]
    fn empty_vault_key() {
        let email = "test@test.test";
        let res = create_signature_body(email, vec![]);
        let mut expected = email.as_bytes().to_vec();
        expected.push(b'|');
        assert_eq!(expected, res);
    }

    #[test]
    fn empty_email_and_vault_key() {
        let res = create_signature_body("", vec![]);
        assert_eq!(vec![b'|'], res);
    }
}
