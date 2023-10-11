use proton_pass_common::invite::create_signature_body;

pub struct NewUserInviteCreator;

impl NewUserInviteCreator {
    pub fn new() -> Self {
        Self
    }

    pub fn create_signature_body(&self, email: String, vault_key: Vec<u8>) -> Vec<u8> {
        create_signature_body(&email, vault_key)
    }
}
