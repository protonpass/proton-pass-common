/*
 *  Copyright (c) 2026 Proton AG
 *  This file is part of Proton AG and Proton Pass.
 *
 *  Proton Pass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Proton Pass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Proton Pass.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

use crate::{CreditCardItem, CustomItem, IdentityItem, LoginItem, SshKeyItem, WifiItem};
use crate::{Item, ItemContent, ItemExtraField, ItemExtraFieldContent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Text(String),
    Hidden(String),
    Totp(String),
}

impl Field {
    pub fn value(&self) -> String {
        match self {
            Field::Text(s) => s.clone(),
            Field::Hidden(s) => s.clone(),
            Field::Totp(s) => s.clone(),
        }
    }
}

impl ItemExtraField {
    pub fn value(&self) -> String {
        match &self.content {
            ItemExtraFieldContent::Text(text) => text.to_string(),
            ItemExtraFieldContent::Totp(totp) => totp.to_string(),
            ItemExtraFieldContent::Hidden(value) => value.to_string(),
            ItemExtraFieldContent::Timestamp(timestamp) => format!("{timestamp}"),
        }
    }

    pub fn as_field(&self) -> Field {
        match &self.content {
            ItemExtraFieldContent::Text(text) => Field::Text(text.to_string()),
            ItemExtraFieldContent::Totp(totp) => Field::Totp(totp.to_string()),
            ItemExtraFieldContent::Hidden(value) => Field::Hidden(value.to_string()),
            ItemExtraFieldContent::Timestamp(timestamp) => Field::Text(format!("{timestamp}")),
        }
    }
}

impl Item {
    pub fn get_field(&self, field: &str) -> Option<Field> {
        let fields = self.fields();
        let field_query = field.to_lowercase();
        let res: Option<(String, Field)> = fields.into_iter().find(|(name, _)| name.to_lowercase() == field_query);
        res.map(|(_, f)| f)
    }

    /// Returns all fields in the item as a vector of (field_name, Field) tuples
    pub fn fields(&self) -> Vec<(String, Field)> {
        let mut fields = Vec::new();

        // Add basic fields if they're not empty
        if !self.content.title.is_empty() {
            fields.push(("title".to_string(), Field::Text(self.content.title.clone())));
        }
        if !self.content.note.is_empty() {
            fields.push(("note".to_string(), Field::Text(self.content.note.clone())));
        }

        // Add extra fields
        for extra_field in self.content.extra_fields.iter() {
            fields.push((extra_field.name.clone(), extra_field.as_field()));
        }

        // Add specific fields
        match &self.content.content {
            ItemContent::Note(_) => {}
            ItemContent::Alias(_) => {}
            ItemContent::Login(login) => {
                self.add_login_fields(login, &mut fields);
            }
            ItemContent::CreditCard(cc) => {
                self.add_cc_fields(cc, &mut fields);
            }
            ItemContent::Identity(identity) => {
                self.add_identity_fields(identity, &mut fields);
            }
            ItemContent::SshKey(ssh) => {
                self.add_ssh_fields(ssh, &mut fields);
            }
            ItemContent::Wifi(wifi) => {
                self.add_wifi_fields(wifi, &mut fields);
            }
            ItemContent::Custom(custom) => {
                self.add_custom_fields(custom, &mut fields);
            }
        }

        fields
    }

    fn add_login_fields(&self, login: &LoginItem, fields: &mut Vec<(String, Field)>) {
        if !login.email.is_empty() {
            fields.push(("email".to_string(), Field::Text(login.email.clone())));
        }
        if !login.username.is_empty() {
            fields.push(("username".to_string(), Field::Text(login.username.clone())));
        }
        if !login.password.is_empty() {
            fields.push(("password".to_string(), Field::Text(login.password.clone())));
        }
        if !login.totp_uri.is_empty() {
            fields.push(("totp".to_string(), Field::Totp(login.totp_uri.clone())));
            fields.push(("totp_uri".to_string(), Field::Totp(login.totp_uri.clone())));
        }
        if !login.urls.is_empty() {
            fields.push(("urls".to_string(), Field::Text(login.urls.join(", "))));
        }
    }

    fn add_cc_fields(&self, cc: &CreditCardItem, fields: &mut Vec<(String, Field)>) {
        if !cc.cardholder_name.is_empty() {
            fields.push(("cardholder_name".to_string(), Field::Text(cc.cardholder_name.clone())));
        }
        fields.push(("card_type".to_string(), Field::Text(format!("{:?}", cc.card_type))));
        if !cc.number.is_empty() {
            fields.push(("number".to_string(), Field::Text(cc.number.clone())));
        }
        if !cc.verification_number.is_empty() {
            fields.push((
                "verification_number".to_string(),
                Field::Text(cc.verification_number.clone()),
            ));
            fields.push(("cvv".to_string(), Field::Text(cc.verification_number.clone())));
            fields.push(("cvc".to_string(), Field::Text(cc.verification_number.clone())));
        }
        if !cc.expiration_date.is_empty() {
            fields.push(("expiration_date".to_string(), Field::Text(cc.expiration_date.clone())));
        }
        if !cc.pin.is_empty() {
            fields.push(("pin".to_string(), Field::Text(cc.pin.clone())));
        }
    }

    fn add_identity_fields(&self, identity: &IdentityItem, fields: &mut Vec<(String, Field)>) {
        if !identity.full_name.is_empty() {
            fields.push(("full_name".to_string(), Field::Text(identity.full_name.clone())));
        }
        if !identity.email.is_empty() {
            fields.push(("email".to_string(), Field::Text(identity.email.clone())));
        }
        if !identity.phone_number.is_empty() {
            fields.push(("phone_number".to_string(), Field::Text(identity.phone_number.clone())));
        }
        if !identity.first_name.is_empty() {
            fields.push(("first_name".to_string(), Field::Text(identity.first_name.clone())));
        }
        if !identity.middle_name.is_empty() {
            fields.push(("middle_name".to_string(), Field::Text(identity.middle_name.clone())));
        }
        if !identity.last_name.is_empty() {
            fields.push(("last_name".to_string(), Field::Text(identity.last_name.clone())));
        }
        if !identity.birthdate.is_empty() {
            fields.push(("birthdate".to_string(), Field::Text(identity.birthdate.clone())));
        }
        if !identity.gender.is_empty() {
            fields.push(("gender".to_string(), Field::Text(identity.gender.clone())));
        }
        if !identity.organization.is_empty() {
            fields.push(("organization".to_string(), Field::Text(identity.organization.clone())));
        }
        if !identity.street_address.is_empty() {
            fields.push(("address".to_string(), Field::Text(identity.street_address.clone())));
        }
        if !identity.zip_or_postal_code.is_empty() {
            fields.push((
                "zip_or_postal_code".to_string(),
                Field::Text(identity.zip_or_postal_code.clone()),
            ));
            fields.push(("zip".to_string(), Field::Text(identity.zip_or_postal_code.clone())));
            fields.push((
                "postal_code".to_string(),
                Field::Text(identity.zip_or_postal_code.clone()),
            ));
        }
        if !identity.city.is_empty() {
            fields.push(("city".to_string(), Field::Text(identity.city.clone())));
        }
        if !identity.state_or_province.is_empty() {
            fields.push((
                "state_or_province".to_string(),
                Field::Text(identity.state_or_province.clone()),
            ));
            fields.push(("state".to_string(), Field::Text(identity.state_or_province.clone())));
            fields.push(("province".to_string(), Field::Text(identity.state_or_province.clone())));
        }
        if !identity.country_or_region.is_empty() {
            fields.push((
                "country_or_region".to_string(),
                Field::Text(identity.country_or_region.clone()),
            ));
            fields.push(("country".to_string(), Field::Text(identity.country_or_region.clone())));
            fields.push(("region".to_string(), Field::Text(identity.country_or_region.clone())));
        }
        if !identity.social_security_number.is_empty() {
            fields.push((
                "social_security_number".to_string(),
                Field::Text(identity.social_security_number.clone()),
            ));
            fields.push(("ssn".to_string(), Field::Text(identity.social_security_number.clone())));
        }
        if !identity.passport_number.is_empty() {
            fields.push((
                "passport_number".to_string(),
                Field::Text(identity.passport_number.clone()),
            ));
            fields.push(("passport".to_string(), Field::Text(identity.passport_number.clone())));
        }
        if !identity.license_number.is_empty() {
            fields.push((
                "license_number".to_string(),
                Field::Text(identity.license_number.clone()),
            ));
        }
        if !identity.website.is_empty() {
            fields.push(("website".to_string(), Field::Text(identity.website.clone())));
        }
        if !identity.company.is_empty() {
            fields.push(("company".to_string(), Field::Text(identity.company.clone())));
        }
        if !identity.job_title.is_empty() {
            fields.push(("job_title".to_string(), Field::Text(identity.job_title.clone())));
        }
    }

    fn add_ssh_fields(&self, ssh: &SshKeyItem, fields: &mut Vec<(String, Field)>) {
        if !ssh.private_key.is_empty() {
            for k in ["private_key", "private key"] {
                fields.push((k.to_string(), Field::Text(ssh.private_key.clone())));
            }
        }
        if !ssh.public_key.is_empty() {
            for k in ["public_key", "public key"] {
                fields.push((k.to_string(), Field::Text(ssh.public_key.clone())));
            }
        }
    }

    fn add_wifi_fields(&self, wifi: &WifiItem, fields: &mut Vec<(String, Field)>) {
        if !wifi.ssid.is_empty() {
            fields.push(("ssid".to_string(), Field::Text(wifi.ssid.clone())));
        }
        if !wifi.password.is_empty() {
            fields.push(("password".to_string(), Field::Text(wifi.password.clone())));
        }
        fields.push(("security".to_string(), Field::Text(format!("{:?}", wifi.security))));
    }

    fn add_custom_fields(&self, custom: &CustomItem, fields: &mut Vec<(String, Field)>) {
        for section in &custom.sections {
            for section_field in &section.section_fields {
                fields.push((section_field.name.clone(), section_field.as_field()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AliasItem, CardType, CustomSection, ItemData, ItemId, ItemState, NoteItem, ShareId, VaultId, WifiSecurity,
    };

    // Helper functions to create default items for testing
    fn create_login_item() -> LoginItem {
        LoginItem {
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            password: "secretpass".to_string(),
            urls: vec!["https://example.com".to_string(), "https://test.com".to_string()],
            totp_uri: "otpauth://totp/test".to_string(),
            passkeys: vec![],
        }
    }

    fn create_credit_card_item() -> CreditCardItem {
        CreditCardItem {
            cardholder_name: "John Doe".to_string(),
            card_type: CardType::Visa,
            number: "4111111111111111".to_string(),
            verification_number: "123".to_string(),
            expiration_date: "12/25".to_string(),
            pin: "1234".to_string(),
        }
    }

    fn create_identity_item() -> Box<IdentityItem> {
        Box::new(IdentityItem {
            full_name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            phone_number: "+1234567890".to_string(),
            first_name: "John".to_string(),
            middle_name: "Michael".to_string(),
            last_name: "Doe".to_string(),
            birthdate: "1990-01-01".to_string(),
            gender: "Male".to_string(),
            extra_personal_details: vec![],
            organization: "Test Corp".to_string(),
            street_address: "123 Main St".to_string(),
            zip_or_postal_code: "12345".to_string(),
            city: "Test City".to_string(),
            state_or_province: "Test State".to_string(),
            country_or_region: "Test Country".to_string(),
            floor: String::new(),
            county: String::new(),
            extra_address_details: vec![],
            social_security_number: "123-45-6789".to_string(),
            passport_number: "A1234567".to_string(),
            license_number: "D123456789".to_string(),
            website: "https://johndoe.com".to_string(),
            x_handle: String::new(),
            second_phone_number: String::new(),
            linkedin: String::new(),
            reddit: String::new(),
            facebook: String::new(),
            yahoo: String::new(),
            instagram: String::new(),
            extra_contact_details: vec![],
            company: "Acme Inc".to_string(),
            job_title: "Software Engineer".to_string(),
            personal_website: String::new(),
            work_phone_number: String::new(),
            work_email: String::new(),
            extra_work_details: vec![],
            extra_sections: vec![],
        })
    }

    fn create_ssh_key_item() -> SshKeyItem {
        SshKeyItem {
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...".to_string(),
            public_key: "ssh-rsa AAAAB3NzaC1yc2E...".to_string(),
            sections: vec![],
        }
    }

    fn create_wifi_item() -> WifiItem {
        WifiItem {
            ssid: "TestNetwork".to_string(),
            password: "wifipass123".to_string(),
            security: WifiSecurity::WPA2,
            sections: vec![],
        }
    }

    fn create_custom_item() -> CustomItem {
        CustomItem {
            sections: vec![CustomSection {
                section_name: "Section1".to_string(),
                section_fields: vec![
                    ItemExtraField {
                        name: "custom_field1".to_string(),
                        content: ItemExtraFieldContent::Text("value1".to_string()),
                    },
                    ItemExtraField {
                        name: "custom_field2".to_string(),
                        content: ItemExtraFieldContent::Hidden("secret_value".to_string()),
                    },
                ],
            }],
        }
    }

    fn create_item_with_content(content: ItemContent) -> Item {
        Item {
            id: ItemId::new("test_id".to_string()),
            share_id: ShareId::new("share_id".to_string()),
            vault_id: VaultId::new("vault_id".to_string()),
            state: ItemState::Active,
            content: ItemData {
                title: "Test Item".to_string(),
                note: "Test note".to_string(),
                item_uuid: "uuid".to_string(),
                content,
                extra_fields: vec![ItemExtraField {
                    name: "extra_field".to_string(),
                    content: ItemExtraFieldContent::Text("extra_value".to_string()),
                }],
                platform_specific: None,
            },
            flags: vec![],
            create_time: jiff::Timestamp::from_second(1234567890)
                .unwrap()
                .to_zoned(jiff::tz::TimeZone::UTC)
                .datetime(),
            modify_time: jiff::Timestamp::from_second(1234567890)
                .unwrap()
                .to_zoned(jiff::tz::TimeZone::UTC)
                .datetime(),
            folder_id: None,
        }
    }

    #[test]
    fn test_get_field_basic_fields() {
        let item = create_item_with_content(ItemContent::Note(NoteItem));

        assert_eq!(item.get_field("title"), Some(Field::Text("Test Item".to_string())));
        assert_eq!(item.get_field("note"), Some(Field::Text("Test note".to_string())));
    }

    #[test]
    fn test_get_field_extra_fields() {
        let item = create_item_with_content(ItemContent::Note(NoteItem));

        assert_eq!(
            item.get_field("extra_field"),
            Some(Field::Text("extra_value".to_string()))
        );
        assert_eq!(
            item.get_field("EXTRA_FIELD"),
            Some(Field::Text("extra_value".to_string()))
        );
        assert_eq!(item.get_field("nonexistent"), None);
    }

    #[test]
    fn test_login_item_fields() {
        let item = create_item_with_content(ItemContent::Login(create_login_item()));

        assert_eq!(
            item.get_field("email"),
            Some(Field::Text("test@example.com".to_string()))
        );
        assert_eq!(
            item.get_field("EMAIL"),
            Some(Field::Text("test@example.com".to_string()))
        );
        assert_eq!(item.get_field("username"), Some(Field::Text("testuser".to_string())));
        assert_eq!(item.get_field("password"), Some(Field::Text("secretpass".to_string())));
        assert_eq!(
            item.get_field("totp_uri"),
            Some(Field::Totp("otpauth://totp/test".to_string()))
        );
        assert_eq!(
            item.get_field("totp"),
            Some(Field::Totp("otpauth://totp/test".to_string()))
        );
        assert_eq!(
            item.get_field("urls"),
            Some(Field::Text("https://example.com, https://test.com".to_string()))
        );
    }

    #[test]
    fn test_credit_card_item_fields() {
        let item = create_item_with_content(ItemContent::CreditCard(create_credit_card_item()));

        assert_eq!(
            item.get_field("cardholder_name"),
            Some(Field::Text("John Doe".to_string()))
        );
        assert_eq!(item.get_field("card_type"), Some(Field::Text("Visa".to_string())));
        assert_eq!(
            item.get_field("number"),
            Some(Field::Text("4111111111111111".to_string()))
        );
        assert_eq!(
            item.get_field("verification_number"),
            Some(Field::Text("123".to_string()))
        );
        assert_eq!(item.get_field("cvv"), Some(Field::Text("123".to_string())));
        assert_eq!(item.get_field("cvc"), Some(Field::Text("123".to_string())));
        assert_eq!(
            item.get_field("expiration_date"),
            Some(Field::Text("12/25".to_string()))
        );
        assert_eq!(item.get_field("pin"), Some(Field::Text("1234".to_string())));
    }

    #[test]
    fn test_identity_item_fields() {
        let item = create_item_with_content(ItemContent::Identity(create_identity_item()));

        assert_eq!(item.get_field("full_name"), Some(Field::Text("John Doe".to_string())));
        assert_eq!(
            item.get_field("email"),
            Some(Field::Text("john@example.com".to_string()))
        );
        assert_eq!(
            item.get_field("phone_number"),
            Some(Field::Text("+1234567890".to_string()))
        );
        assert_eq!(item.get_field("first_name"), Some(Field::Text("John".to_string())));
        assert_eq!(item.get_field("middle_name"), Some(Field::Text("Michael".to_string())));
        assert_eq!(item.get_field("last_name"), Some(Field::Text("Doe".to_string())));
        assert_eq!(item.get_field("birthdate"), Some(Field::Text("1990-01-01".to_string())));
        assert_eq!(item.get_field("gender"), Some(Field::Text("Male".to_string())));
        assert_eq!(
            item.get_field("organization"),
            Some(Field::Text("Test Corp".to_string()))
        );
        assert_eq!(item.get_field("address"), Some(Field::Text("123 Main St".to_string())));
        assert_eq!(
            item.get_field("zip_or_postal_code"),
            Some(Field::Text("12345".to_string()))
        );
        assert_eq!(item.get_field("zip"), Some(Field::Text("12345".to_string())));
        assert_eq!(item.get_field("postal_code"), Some(Field::Text("12345".to_string())));
        assert_eq!(item.get_field("city"), Some(Field::Text("Test City".to_string())));
        assert_eq!(
            item.get_field("state_or_province"),
            Some(Field::Text("Test State".to_string()))
        );
        assert_eq!(item.get_field("state"), Some(Field::Text("Test State".to_string())));
        assert_eq!(item.get_field("province"), Some(Field::Text("Test State".to_string())));
        assert_eq!(
            item.get_field("country_or_region"),
            Some(Field::Text("Test Country".to_string()))
        );
        assert_eq!(item.get_field("country"), Some(Field::Text("Test Country".to_string())));
        assert_eq!(item.get_field("region"), Some(Field::Text("Test Country".to_string())));
        assert_eq!(
            item.get_field("social_security_number"),
            Some(Field::Text("123-45-6789".to_string()))
        );
        assert_eq!(item.get_field("ssn"), Some(Field::Text("123-45-6789".to_string())));
        assert_eq!(
            item.get_field("passport_number"),
            Some(Field::Text("A1234567".to_string()))
        );
        assert_eq!(item.get_field("passport"), Some(Field::Text("A1234567".to_string())));
        assert_eq!(
            item.get_field("license_number"),
            Some(Field::Text("D123456789".to_string()))
        );
        assert_eq!(
            item.get_field("website"),
            Some(Field::Text("https://johndoe.com".to_string()))
        );
        assert_eq!(item.get_field("company"), Some(Field::Text("Acme Inc".to_string())));
        assert_eq!(
            item.get_field("job_title"),
            Some(Field::Text("Software Engineer".to_string()))
        );
    }

    #[test]
    fn test_ssh_key_item_fields() {
        let item = create_item_with_content(ItemContent::SshKey(create_ssh_key_item()));

        assert_eq!(
            item.get_field("private_key"),
            Some(Field::Text(
                "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...".to_string()
            ))
        );
        assert_eq!(
            item.get_field("public_key"),
            Some(Field::Text("ssh-rsa AAAAB3NzaC1yc2E...".to_string()))
        );
    }

    #[test]
    fn test_wifi_item_fields() {
        let item = create_item_with_content(ItemContent::Wifi(create_wifi_item()));

        assert_eq!(item.get_field("ssid"), Some(Field::Text("TestNetwork".to_string())));
        assert_eq!(item.get_field("password"), Some(Field::Text("wifipass123".to_string())));
        assert_eq!(item.get_field("security"), Some(Field::Text("WPA2".to_string())));
    }

    #[test]
    fn test_custom_item_fields() {
        let item = create_item_with_content(ItemContent::Custom(create_custom_item()));

        assert_eq!(item.get_field("custom_field1"), Some(Field::Text("value1".to_string())));
        assert_eq!(item.get_field("CUSTOM_FIELD1"), Some(Field::Text("value1".to_string())));
        assert_eq!(
            item.get_field("custom_field2"),
            Some(Field::Hidden("secret_value".to_string()))
        );
        assert_eq!(item.get_field("nonexistent_field"), None);
    }

    #[test]
    fn test_note_and_alias_items() {
        let note_item = create_item_with_content(ItemContent::Note(NoteItem));
        let alias_item = create_item_with_content(ItemContent::Alias(AliasItem));

        // Should only find basic fields and extra fields
        assert_eq!(note_item.get_field("title"), Some(Field::Text("Test Item".to_string())));
        assert_eq!(note_item.get_field("note"), Some(Field::Text("Test note".to_string())));
        assert_eq!(
            note_item.get_field("extra_field"),
            Some(Field::Text("extra_value".to_string()))
        );
        assert_eq!(note_item.get_field("nonexistent"), None);

        assert_eq!(
            alias_item.get_field("title"),
            Some(Field::Text("Test Item".to_string()))
        );
        assert_eq!(alias_item.get_field("note"), Some(Field::Text("Test note".to_string())));
        assert_eq!(
            alias_item.get_field("extra_field"),
            Some(Field::Text("extra_value".to_string()))
        );
        assert_eq!(alias_item.get_field("nonexistent"), None);
    }

    #[test]
    fn test_case_insensitive_matching() {
        let item = create_item_with_content(ItemContent::Login(create_login_item()));

        // Test various case combinations
        assert_eq!(
            item.get_field("EMAIL"),
            Some(Field::Text("test@example.com".to_string()))
        );
        assert_eq!(
            item.get_field("Email"),
            Some(Field::Text("test@example.com".to_string()))
        );
        assert_eq!(
            item.get_field("eMaIl"),
            Some(Field::Text("test@example.com".to_string()))
        );
        assert_eq!(item.get_field("USERNAME"), Some(Field::Text("testuser".to_string())));
        assert_eq!(item.get_field("Password"), Some(Field::Text("secretpass".to_string())));
        assert_eq!(
            item.get_field("TOTP_URI"),
            Some(Field::Totp("otpauth://totp/test".to_string()))
        );
    }

    #[test]
    fn test_empty_urls_in_login() {
        let mut login = create_login_item();
        login.urls = vec![];
        let item = create_item_with_content(ItemContent::Login(login));
        assert!(item.get_field("urls").is_none());
    }

    #[test]
    fn test_single_url_in_login() {
        let mut login = create_login_item();
        login.urls = vec!["https://single.com".to_string()];
        let item = create_item_with_content(ItemContent::Login(login));

        assert_eq!(
            item.get_field("urls"),
            Some(Field::Text("https://single.com".to_string()))
        );
    }

    #[test]
    fn test_card_type_formatting() {
        let mut cc = create_credit_card_item();
        cc.card_type = CardType::AmericanExpress;
        let item = create_item_with_content(ItemContent::CreditCard(cc));

        assert_eq!(
            item.get_field("card_type"),
            Some(Field::Text("AmericanExpress".to_string()))
        );
    }

    #[test]
    fn test_wifi_security_formatting() {
        let mut wifi = create_wifi_item();
        wifi.security = WifiSecurity::WPA3;
        let item = create_item_with_content(ItemContent::Wifi(wifi));

        assert_eq!(item.get_field("security"), Some(Field::Text("WPA3".to_string())));
    }
}
