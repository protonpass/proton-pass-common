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

mod attachment;
mod field;
mod flags;

use crate::protos::item::item_v1;
use anyhow::{Context, Result, anyhow};
pub use attachment::*;
pub use field::Field;
pub use flags::*;
use protobuf::Message;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct ItemId(pub(crate) String);
display_for_basic!(ItemId);

impl ItemId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum ItemState {
    Active = 1,
    Trashed = 2,
}

impl TryFrom<u8> for ItemState {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(ItemState::Active),
            2 => Ok(ItemState::Trashed),
            _ => Err(anyhow!("Invalid item state value: {}", value)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateFieldResult {
    FieldUpdated,
    CustomFieldCreated,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, Default)]
pub struct AllowedAndroidApp {
    pub package_name: String,
    pub hashes: Vec<String>,
    pub app_name: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, Default)]
pub struct AndroidSpecific {
    pub allowed_apps: Vec<AllowedAndroidApp>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, Default)]
pub struct PlatformSpecific {
    pub android: Option<AndroidSpecific>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct ItemData {
    pub title: String,
    pub note: String,
    pub item_uuid: String,
    pub content: ItemContent,
    pub extra_fields: Vec<ItemExtraField>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub platform_specific: Option<PlatformSpecific>,
}

impl ItemData {
    pub fn new(
        title: String,
        note: String,
        item_uuid: String,
        content: ItemContent,
        extra_fields: Vec<ItemExtraField>,
    ) -> Result<Self> {
        if title.is_empty() {
            return Err(anyhow!("The item title cannot be empty."));
        }

        Ok(Self {
            title,
            note,
            item_uuid,
            content,
            extra_fields,
            platform_specific: None,
        })
    }

    pub fn serialize(self) -> Result<Vec<u8>> {
        let as_proto = item_v1::Item::from(self);
        as_proto
            .write_to_bytes()
            .map_err(|e| anyhow!("Error serializing item to proto: {}", e))
    }

    pub fn pretty_print(&self) -> String {
        let mut out = String::new();

        let item_content = self.content.pretty_print();
        if !item_content.is_empty() {
            out.push_str(&item_content);
        }

        if !self.extra_fields.is_empty() {
            out.push_str("\n\nExtra fields:\n");
            for field in &self.extra_fields {
                out.push_str(format!("  - {}: {:?}", field.name, field.content).as_str());
            }
        }

        out
    }

    pub fn perform_update(original: &[u8], new: &Self) -> Result<Vec<u8>> {
        let mut original_as_proto =
            item_v1::Item::parse_from_bytes(original).context("Error decoding Item from proto")?;
        let new_as_proto = item_v1::Item::from(new.clone());
        let new_as_proto_serialized = new_as_proto.to_vec().context("Error serializing item to proto")?;

        // Clear repeated fields that should be replaced, not appended
        // This prevents duplication while still preserving unknown fields from newer protobuf versions
        original_as_proto.extra_fields.clear();

        // Clear fields marked as "repeated" in content based on the content type
        if let Some(content) = original_as_proto.content.as_mut()
            && let Some(content_inner) = content.content.as_mut()
        {
            match content_inner {
                item_v1::content::Content::Login(login_mut) => {
                    login_mut.urls.clear();
                    login_mut.passkeys.clear();
                }
                item_v1::content::Content::Custom(custom_mut) => {
                    custom_mut.sections.clear();
                }
                item_v1::content::Content::Identity(identity_mut) => {
                    identity_mut.extra_personal_details.clear();
                    identity_mut.extra_address_details.clear();
                    identity_mut.extra_contact_details.clear();
                    identity_mut.extra_work_details.clear();
                    identity_mut.extra_sections.clear();
                }
                item_v1::content::Content::SshKey(ssh_mut) => {
                    ssh_mut.sections.clear();
                }
                item_v1::content::Content::Wifi(wifi_mut) => {
                    wifi_mut.sections.clear();
                }
                _ => {}
            }
        }

        original_as_proto
            .merge_from_bytes(&new_as_proto_serialized)
            .context("Error performing item updates")?;

        let updated_serialized = original_as_proto
            .to_vec()
            .context("Error serializing updated item to proto")?;
        Ok(updated_serialized)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let as_proto = item_v1::Item::parse_from_bytes(data).context("Error decoding Item from proto")?;

        Ok(Self::from(as_proto))
    }

    pub fn generate_uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Update a field in the item. Returns whether the field was updated or a new custom field was created.
    pub fn update_field(&mut self, field_name: &str, field_value: &str) -> Result<UpdateFieldResult> {
        let field_name_lower = field_name.to_lowercase();

        // Handle basic fields
        if field_name_lower == "title" {
            self.title = field_value.to_string();
            return Ok(UpdateFieldResult::FieldUpdated);
        }
        if field_name_lower == "note" {
            self.note = field_value.to_string();
            return Ok(UpdateFieldResult::FieldUpdated);
        }

        // Check if this is an existing extra field
        for extra_field in self.extra_fields.iter_mut() {
            if extra_field.name.to_lowercase() == field_name_lower {
                // Don't allow updating timestamp or totp fields
                match &extra_field.content {
                    ItemExtraFieldContent::Timestamp(_) => {
                        return Err(anyhow!("Cannot update timestamp field '{}'", field_name));
                    }
                    ItemExtraFieldContent::Totp(_) => {
                        return Err(anyhow!("Editing TOTP fields is unsupported"));
                    }
                    ItemExtraFieldContent::Hidden(_) => {
                        extra_field.content = ItemExtraFieldContent::Hidden(field_value.to_string());
                    }
                    ItemExtraFieldContent::Text(_) => {
                        extra_field.content = ItemExtraFieldContent::Text(field_value.to_string());
                    }
                }
                return Ok(UpdateFieldResult::FieldUpdated);
            }
        }

        // Handle item-type-specific fields
        match &mut self.content {
            ItemContent::Login(login) => {
                if Self::update_login_field(login, &field_name_lower, field_value) {
                    return Ok(UpdateFieldResult::FieldUpdated);
                }
            }
            ItemContent::CreditCard(cc) => {
                if Self::update_credit_card_field(cc, &field_name_lower, field_value) {
                    return Ok(UpdateFieldResult::FieldUpdated);
                }
            }
            ItemContent::Identity(identity) => {
                if Self::update_identity_field(identity, &field_name_lower, field_value) {
                    return Ok(UpdateFieldResult::FieldUpdated);
                }
            }
            ItemContent::SshKey(ssh) => {
                if Self::update_ssh_field(ssh, &field_name_lower, field_value) {
                    return Ok(UpdateFieldResult::FieldUpdated);
                }
            }
            ItemContent::Wifi(wifi) => {
                if Self::update_wifi_field(wifi, &field_name_lower, field_value) {
                    return Ok(UpdateFieldResult::FieldUpdated);
                }
            }
            ItemContent::Custom(custom) => {
                if Self::update_custom_field(custom, &field_name_lower, field_value) {
                    return Ok(UpdateFieldResult::FieldUpdated);
                }
            }
            ItemContent::Note(_) | ItemContent::Alias(_) => {}
        }

        // Field not found, create a new custom field
        self.extra_fields.push(ItemExtraField {
            name: field_name.to_string(),
            content: ItemExtraFieldContent::Text(field_value.to_string()),
        });
        Ok(UpdateFieldResult::CustomFieldCreated)
    }

    fn update_login_field(login: &mut LoginItem, field_name: &str, field_value: &str) -> bool {
        match field_name {
            "email" => {
                login.email = field_value.to_string();
                true
            }
            "username" => {
                login.username = field_value.to_string();
                true
            }
            "password" => {
                login.password = field_value.to_string();
                true
            }
            "totp_uri" | "totp" => {
                // TOTP fields cannot be edited
                false
            }
            "urls" => {
                // Split by comma and trim whitespace
                login.urls = field_value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                true
            }
            _ => false,
        }
    }

    fn update_credit_card_field(cc: &mut CreditCardItem, field_name: &str, field_value: &str) -> bool {
        match field_name {
            "cardholder_name" => {
                cc.cardholder_name = field_value.to_string();
                true
            }
            "number" => {
                cc.number = field_value.to_string();
                true
            }
            "verification_number" | "cvv" | "cvc" => {
                cc.verification_number = field_value.to_string();
                true
            }
            "expiration_date" => {
                cc.expiration_date = field_value.to_string();
                true
            }
            "pin" => {
                cc.pin = field_value.to_string();
                true
            }
            _ => false,
        }
    }

    fn update_identity_field(identity: &mut IdentityItem, field_name: &str, field_value: &str) -> bool {
        match field_name {
            "full_name" => {
                identity.full_name = field_value.to_string();
                true
            }
            "email" => {
                identity.email = field_value.to_string();
                true
            }
            "phone_number" => {
                identity.phone_number = field_value.to_string();
                true
            }
            "first_name" => {
                identity.first_name = field_value.to_string();
                true
            }
            "middle_name" => {
                identity.middle_name = field_value.to_string();
                true
            }
            "last_name" => {
                identity.last_name = field_value.to_string();
                true
            }
            "birthdate" => {
                identity.birthdate = field_value.to_string();
                true
            }
            "gender" => {
                identity.gender = field_value.to_string();
                true
            }
            "organization" => {
                identity.organization = field_value.to_string();
                true
            }
            "street_address" | "address" => {
                identity.street_address = field_value.to_string();
                true
            }
            "zip_or_postal_code" | "zip" | "postal_code" => {
                identity.zip_or_postal_code = field_value.to_string();
                true
            }
            "city" => {
                identity.city = field_value.to_string();
                true
            }
            "state_or_province" | "state" | "province" => {
                identity.state_or_province = field_value.to_string();
                true
            }
            "country_or_region" | "country" | "region" => {
                identity.country_or_region = field_value.to_string();
                true
            }
            "social_security_number" | "ssn" => {
                identity.social_security_number = field_value.to_string();
                true
            }
            "passport_number" | "passport" => {
                identity.passport_number = field_value.to_string();
                true
            }
            "license_number" => {
                identity.license_number = field_value.to_string();
                true
            }
            "website" => {
                identity.website = field_value.to_string();
                true
            }
            "company" => {
                identity.company = field_value.to_string();
                true
            }
            "job_title" => {
                identity.job_title = field_value.to_string();
                true
            }
            _ => false,
        }
    }

    fn update_ssh_field(ssh: &mut SshKeyItem, field_name: &str, field_value: &str) -> bool {
        match field_name {
            "private_key" | "private key" => {
                ssh.private_key = field_value.to_string();
                true
            }
            "public_key" | "public key" => {
                ssh.public_key = field_value.to_string();
                true
            }
            _ => false,
        }
    }

    fn update_wifi_field(wifi: &mut WifiItem, field_name: &str, field_value: &str) -> bool {
        match field_name {
            "ssid" => {
                wifi.ssid = field_value.to_string();
                true
            }
            "password" => {
                wifi.password = field_value.to_string();
                true
            }
            "security" => {
                // Try to parse the security type
                wifi.security = match field_value.to_lowercase().as_str() {
                    "wpa" => WifiSecurity::WPA,
                    "wpa2" => WifiSecurity::WPA2,
                    "wpa3" => WifiSecurity::WPA3,
                    "wep" => WifiSecurity::WEP,
                    _ => wifi.security.clone(), // Keep existing if invalid
                };
                true
            }
            _ => false,
        }
    }

    fn update_custom_field(custom: &mut CustomItem, field_name: &str, field_value: &str) -> bool {
        // Search through all sections for the first matching field
        for section in &mut custom.sections {
            for field in &mut section.section_fields {
                if field.name.to_lowercase() == field_name {
                    // Update the field preserving type, but skip timestamp and totp fields
                    match &field.content {
                        ItemExtraFieldContent::Hidden(_) => {
                            field.content = ItemExtraFieldContent::Hidden(field_value.to_string());
                        }
                        ItemExtraFieldContent::Text(_) => {
                            field.content = ItemExtraFieldContent::Text(field_value.to_string());
                        }
                        ItemExtraFieldContent::Totp(_) | ItemExtraFieldContent::Timestamp(_) => {
                            // Don't update totp or timestamp fields in custom sections
                            continue;
                        }
                    }
                    return true;
                }
            }
        }
        false
    }
}

impl From<AllowedAndroidApp> for item_v1::AllowedAndroidApp {
    fn from(value: AllowedAndroidApp) -> Self {
        item_v1::AllowedAndroidApp {
            package_name: value.package_name,
            hashes: value.hashes,
            app_name: value.app_name,
            ..Default::default()
        }
    }
}

impl From<item_v1::AllowedAndroidApp> for AllowedAndroidApp {
    fn from(value: item_v1::AllowedAndroidApp) -> Self {
        Self {
            package_name: value.package_name,
            hashes: value.hashes,
            app_name: value.app_name,
        }
    }
}

impl From<AndroidSpecific> for item_v1::AndroidSpecific {
    fn from(value: AndroidSpecific) -> Self {
        item_v1::AndroidSpecific {
            allowed_apps: value
                .allowed_apps
                .into_iter()
                .map(item_v1::AllowedAndroidApp::from)
                .collect(),
            ..Default::default()
        }
    }
}

impl From<item_v1::AndroidSpecific> for AndroidSpecific {
    fn from(value: item_v1::AndroidSpecific) -> Self {
        Self {
            allowed_apps: value.allowed_apps.into_iter().map(AllowedAndroidApp::from).collect(),
        }
    }
}

impl From<PlatformSpecific> for item_v1::PlatformSpecific {
    fn from(value: PlatformSpecific) -> Self {
        item_v1::PlatformSpecific {
            android: value
                .android
                .map(|a| protobuf::MessageField::some(item_v1::AndroidSpecific::from(a)))
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl From<item_v1::PlatformSpecific> for PlatformSpecific {
    fn from(value: item_v1::PlatformSpecific) -> Self {
        Self {
            android: value.android.into_option().map(AndroidSpecific::from),
        }
    }
}

impl From<ItemData> for item_v1::Item {
    fn from(value: ItemData) -> Self {
        let metadata = item_v1::Metadata {
            name: value.title,
            note: value.note,
            item_uuid: value.item_uuid,
            ..Default::default()
        };

        let content = item_v1::Content {
            content: Some(item_v1::content::Content::from(value.content)),
            ..Default::default()
        };

        item_v1::Item {
            metadata: protobuf::MessageField::some(metadata),
            content: protobuf::MessageField::some(content),
            extra_fields: value.extra_fields.into_iter().map(item_v1::ExtraField::from).collect(),
            platform_specific: value
                .platform_specific
                .map(|ps| protobuf::MessageField::some(item_v1::PlatformSpecific::from(ps)))
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl From<item_v1::Item> for ItemData {
    fn from(value: item_v1::Item) -> Self {
        let metadata = value.metadata.unwrap_or_default();
        let content = value.content.unwrap_or_default();

        Self {
            title: metadata.name,
            note: metadata.note,
            item_uuid: metadata.item_uuid,
            content: ItemContent::from(content),
            extra_fields: value.extra_fields.into_iter().map(ItemExtraField::from).collect(),
            platform_specific: value.platform_specific.into_option().map(PlatformSpecific::from),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct ItemExtraField {
    pub name: String,
    pub content: ItemExtraFieldContent,
}

impl From<ItemExtraField> for item_v1::ExtraField {
    fn from(value: ItemExtraField) -> Self {
        item_v1::ExtraField {
            field_name: value.name,
            content: Some(item_v1::extra_field::Content::from(value.content)),
            ..Default::default()
        }
    }
}

impl From<item_v1::ExtraField> for ItemExtraField {
    fn from(value: item_v1::ExtraField) -> Self {
        Self {
            name: value.field_name,
            content: value
                .content
                .map(ItemExtraFieldContent::from)
                .unwrap_or(ItemExtraFieldContent::Text(String::new())),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub enum ItemExtraFieldContent {
    Text(String),
    Totp(String),
    Hidden(String),
    Timestamp(i64), // Unix timestamp in seconds
}

impl From<ItemExtraFieldContent> for item_v1::extra_field::Content {
    fn from(value: ItemExtraFieldContent) -> Self {
        match value {
            ItemExtraFieldContent::Text(content) => item_v1::extra_field::Content::Text(item_v1::ExtraTextField {
                content,
                ..Default::default()
            }),
            ItemExtraFieldContent::Totp(totp_uri) => item_v1::extra_field::Content::Totp(item_v1::ExtraTotp {
                totp_uri,
                ..Default::default()
            }),
            ItemExtraFieldContent::Hidden(content) => {
                item_v1::extra_field::Content::Hidden(item_v1::ExtraHiddenField {
                    content,
                    ..Default::default()
                })
            }
            ItemExtraFieldContent::Timestamp(timestamp) => {
                let proto_timestamp = protobuf::well_known_types::timestamp::Timestamp {
                    seconds: timestamp,
                    nanos: 0,
                    ..Default::default()
                };
                item_v1::extra_field::Content::Timestamp(item_v1::ExtraTimestampField {
                    timestamp: protobuf::MessageField::some(proto_timestamp),
                    ..Default::default()
                })
            }
        }
    }
}

impl From<item_v1::extra_field::Content> for ItemExtraFieldContent {
    fn from(value: item_v1::extra_field::Content) -> Self {
        match value {
            item_v1::extra_field::Content::Text(text_field) => ItemExtraFieldContent::Text(text_field.content),
            item_v1::extra_field::Content::Totp(totp_field) => ItemExtraFieldContent::Totp(totp_field.totp_uri),
            item_v1::extra_field::Content::Hidden(hidden_field) => ItemExtraFieldContent::Hidden(hidden_field.content),
            item_v1::extra_field::Content::Timestamp(timestamp_field) => {
                let timestamp = timestamp_field.timestamp.unwrap_or_default();
                ItemExtraFieldContent::Timestamp(timestamp.seconds)
            }
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub enum ItemContent {
    Note(NoteItem),
    Login(LoginItem),
    Alias(AliasItem),
    CreditCard(CreditCardItem),
    Identity(Box<IdentityItem>),
    SshKey(SshKeyItem),
    Wifi(WifiItem),
    Custom(CustomItem),
}

impl ItemContent {
    pub fn pretty_print(&self) -> String {
        match self {
            ItemContent::Note(v) => v.pretty_print(),
            ItemContent::Login(v) => v.pretty_print(),
            ItemContent::Alias(v) => v.pretty_print(),
            ItemContent::CreditCard(v) => v.pretty_print(),
            ItemContent::Identity(v) => v.pretty_print(),
            ItemContent::SshKey(v) => v.pretty_print(),
            ItemContent::Wifi(v) => v.pretty_print(),
            ItemContent::Custom(v) => v.pretty_print(),
        }
    }
}

impl From<ItemContent> for item_v1::content::Content {
    fn from(value: ItemContent) -> Self {
        match value {
            ItemContent::Note(note) => item_v1::content::Content::Note(item_v1::ItemNote::from(note)),
            ItemContent::Login(login) => item_v1::content::Content::Login(item_v1::ItemLogin::from(login)),
            ItemContent::Alias(alias) => item_v1::content::Content::Alias(item_v1::ItemAlias::from(alias)),
            ItemContent::CreditCard(credit_card) => {
                item_v1::content::Content::CreditCard(item_v1::ItemCreditCard::from(credit_card))
            }
            ItemContent::Identity(identity) => {
                item_v1::content::Content::Identity(item_v1::ItemIdentity::from(*identity))
            }
            ItemContent::SshKey(ssh_key) => item_v1::content::Content::SshKey(item_v1::ItemSSHKey::from(ssh_key)),
            ItemContent::Wifi(wifi) => item_v1::content::Content::Wifi(item_v1::ItemWifi::from(wifi)),
            ItemContent::Custom(custom) => item_v1::content::Content::Custom(item_v1::ItemCustom::from(custom)),
        }
    }
}

impl From<item_v1::Content> for ItemContent {
    fn from(value: item_v1::Content) -> Self {
        match value.content {
            Some(item_v1::content::Content::Note(note)) => ItemContent::Note(NoteItem::from(note)),
            Some(item_v1::content::Content::Login(login)) => ItemContent::Login(LoginItem::from(login)),
            Some(item_v1::content::Content::Alias(alias)) => ItemContent::Alias(AliasItem::from(alias)),
            Some(item_v1::content::Content::CreditCard(credit_card)) => {
                ItemContent::CreditCard(CreditCardItem::from(credit_card))
            }
            Some(item_v1::content::Content::Identity(identity)) => {
                ItemContent::Identity(Box::new(IdentityItem::from(identity)))
            }
            Some(item_v1::content::Content::SshKey(ssh_key)) => ItemContent::SshKey(SshKeyItem::from(ssh_key)),
            Some(item_v1::content::Content::Wifi(wifi)) => ItemContent::Wifi(WifiItem::from(wifi)),
            Some(item_v1::content::Content::Custom(custom)) => ItemContent::Custom(CustomItem::from(custom)),
            None => ItemContent::Note(NoteItem),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct NoteItem;

impl NoteItem {
    pub fn pretty_print(&self) -> String {
        String::new()
    }
}

impl From<NoteItem> for item_v1::ItemNote {
    fn from(_value: NoteItem) -> Self {
        item_v1::ItemNote::default()
    }
}

impl From<item_v1::ItemNote> for NoteItem {
    fn from(_value: item_v1::ItemNote) -> Self {
        NoteItem
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct PasskeyCreationData {
    pub os_name: String,
    pub os_version: String,
    pub device_name: String,
    pub app_version: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct Passkey {
    pub key_id: String,
    pub content: Vec<u8>,
    pub domain: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id: Vec<u8>,
    pub create_time: u32,
    pub note: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub creation_data: Option<PasskeyCreationData>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct LoginItem {
    pub email: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub totp_uri: String,
    pub passkeys: Vec<Passkey>,
}

impl LoginItem {
    pub fn pretty_print(&self) -> String {
        let mut out = String::new();

        if !self.email.is_empty() {
            out.push_str(format!("\n - Email: {}", self.email).as_str());
        }
        if !self.username.is_empty() {
            out.push_str(format!("\n - Username: {}", self.username).as_str());
        }
        if !self.password.is_empty() {
            out.push_str(format!("\n - Password: {}", self.password).as_str());
        }
        if !self.totp_uri.is_empty() {
            out.push_str(format!("\n - TOTP URI: {}", self.totp_uri).as_str());
        }
        if !self.urls.is_empty() {
            out.push_str("\n - URLS");
            for url in &self.urls {
                out.push_str(format!("\n   - {}", url).as_str());
            }
        }

        out
    }
}

impl From<PasskeyCreationData> for item_v1::PasskeyCreationData {
    fn from(value: PasskeyCreationData) -> Self {
        item_v1::PasskeyCreationData {
            os_name: value.os_name,
            os_version: value.os_version,
            device_name: value.device_name,
            app_version: value.app_version,
            ..Default::default()
        }
    }
}

impl From<item_v1::PasskeyCreationData> for PasskeyCreationData {
    fn from(value: item_v1::PasskeyCreationData) -> Self {
        Self {
            os_name: value.os_name,
            os_version: value.os_version,
            device_name: value.device_name,
            app_version: value.app_version,
        }
    }
}

impl From<Passkey> for item_v1::Passkey {
    fn from(value: Passkey) -> Self {
        item_v1::Passkey {
            key_id: value.key_id,
            content: value.content,
            domain: value.domain,
            rp_id: value.rp_id,
            rp_name: value.rp_name,
            user_name: value.user_name,
            user_display_name: value.user_display_name,
            user_id: value.user_id,
            create_time: value.create_time,
            note: value.note,
            credential_id: value.credential_id,
            user_handle: value.user_handle,
            creation_data: value
                .creation_data
                .map(|data| protobuf::MessageField::some(item_v1::PasskeyCreationData::from(data)))
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl From<item_v1::Passkey> for Passkey {
    fn from(value: item_v1::Passkey) -> Self {
        Self {
            key_id: value.key_id,
            content: value.content,
            domain: value.domain,
            rp_id: value.rp_id,
            rp_name: value.rp_name,
            user_name: value.user_name,
            user_display_name: value.user_display_name,
            user_id: value.user_id,
            create_time: value.create_time,
            note: value.note,
            credential_id: value.credential_id,
            user_handle: value.user_handle,
            creation_data: value.creation_data.into_option().map(PasskeyCreationData::from),
        }
    }
}

impl From<LoginItem> for item_v1::ItemLogin {
    fn from(value: LoginItem) -> Self {
        item_v1::ItemLogin {
            item_email: value.email,
            item_username: value.username,
            password: value.password,
            urls: value.urls,
            totp_uri: value.totp_uri,
            passkeys: value.passkeys.into_iter().map(item_v1::Passkey::from).collect(),
            ..Default::default()
        }
    }
}

impl From<item_v1::ItemLogin> for LoginItem {
    fn from(value: item_v1::ItemLogin) -> Self {
        Self {
            email: value.item_email,
            username: value.item_username,
            password: value.password,
            urls: value.urls,
            totp_uri: value.totp_uri,
            passkeys: value.passkeys.into_iter().map(Passkey::from).collect(),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct AliasItem;

impl AliasItem {
    pub fn pretty_print(&self) -> String {
        String::new()
    }
}

impl From<AliasItem> for item_v1::ItemAlias {
    fn from(_value: AliasItem) -> Self {
        item_v1::ItemAlias::default()
    }
}

impl From<item_v1::ItemAlias> for AliasItem {
    fn from(_value: item_v1::ItemAlias) -> Self {
        AliasItem
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct CreditCardItem {
    pub cardholder_name: String,
    pub card_type: CardType,
    pub number: String,
    pub verification_number: String,
    pub expiration_date: String,
    pub pin: String,
}

impl CreditCardItem {
    pub fn pretty_print(&self) -> String {
        let mut out = String::new();
        if !self.cardholder_name.is_empty() {
            out.push_str(format!("\n- Cardholder name: {}", self.cardholder_name).as_str());
        }
        if !self.number.is_empty() {
            out.push_str(format!("\n- Number: {}", self.number).as_str());
        }
        if !self.verification_number.is_empty() {
            out.push_str(format!("\n- Verification number: {}", self.verification_number).as_str());
        }
        if !self.expiration_date.is_empty() {
            out.push_str(format!("\n- Expiration date: {}", self.expiration_date).as_str());
        }
        if !self.pin.is_empty() {
            out.push_str(format!("\n- PIN: {}", self.pin).as_str());
        }
        out
    }
}

impl From<CreditCardItem> for item_v1::ItemCreditCard {
    fn from(value: CreditCardItem) -> Self {
        item_v1::ItemCreditCard {
            cardholder_name: value.cardholder_name,
            card_type: item_v1::CardType::from(value.card_type).into(),
            number: value.number,
            verification_number: value.verification_number,
            expiration_date: value.expiration_date,
            pin: value.pin,
            ..Default::default()
        }
    }
}

impl From<item_v1::ItemCreditCard> for CreditCardItem {
    fn from(value: item_v1::ItemCreditCard) -> Self {
        Self {
            cardholder_name: value.cardholder_name,
            card_type: CardType::from(value.card_type.enum_value_or_default()),
            number: value.number,
            verification_number: value.verification_number,
            expiration_date: value.expiration_date,
            pin: value.pin,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct IdentityItem {
    pub full_name: String,
    pub email: String,
    pub phone_number: String,
    pub first_name: String,
    pub middle_name: String,
    pub last_name: String,
    pub birthdate: String,
    pub gender: String,
    pub extra_personal_details: Vec<ItemExtraField>,
    pub organization: String,
    pub street_address: String,
    pub zip_or_postal_code: String,
    pub city: String,
    pub state_or_province: String,
    pub country_or_region: String,
    pub floor: String,
    pub county: String,
    pub extra_address_details: Vec<ItemExtraField>,
    pub social_security_number: String,
    pub passport_number: String,
    pub license_number: String,
    pub website: String,
    pub x_handle: String,
    pub second_phone_number: String,
    pub linkedin: String,
    pub reddit: String,
    pub facebook: String,
    pub yahoo: String,
    pub instagram: String,
    pub extra_contact_details: Vec<ItemExtraField>,
    pub company: String,
    pub job_title: String,
    pub personal_website: String,
    pub work_phone_number: String,
    pub work_email: String,
    pub extra_work_details: Vec<ItemExtraField>,
    pub extra_sections: Vec<CustomSection>,
}

impl IdentityItem {
    pub fn pretty_print(&self) -> String {
        let mut out = String::new();
        if !self.full_name.is_empty() {
            out.push_str(format!("\n- Full name: {}", self.full_name).as_str());
        }
        if !self.email.is_empty() {
            out.push_str(format!("\n- Email: {}", self.email).as_str());
        }
        if !self.phone_number.is_empty() {
            out.push_str(format!("\n- Phone number: {}", self.phone_number).as_str());
        }
        if !self.first_name.is_empty() {
            out.push_str(format!("\n- First name: {}", self.first_name).as_str());
        }
        if !self.middle_name.is_empty() {
            out.push_str(format!("\n- Middle name: {}", self.middle_name).as_str());
        }
        if !self.last_name.is_empty() {
            out.push_str(format!("\n- Last name: {}", self.last_name).as_str());
        }
        if !self.birthdate.is_empty() {
            out.push_str(format!("\n- Birthdate: {}", self.birthdate).as_str());
        }
        if !self.gender.is_empty() {
            out.push_str(format!("\n- Gender: {}", self.gender).as_str());
        }
        if !self.extra_personal_details.is_empty() {
            out.push_str(
                format!(
                    "\n- Extra personal details: {}",
                    self.extra_personal_details
                        .iter()
                        .map(|d| format!("\n  - {}:{:#?}", d.name, d.content))
                        .collect::<String>()
                )
                .as_str(),
            );
        }
        if !self.organization.is_empty() {
            out.push_str(format!("\n- Organization: {}", self.organization).as_str());
        }
        if !self.street_address.is_empty() {
            out.push_str(format!("\n- Street address: {}", self.street_address).as_str());
        }
        if !self.zip_or_postal_code.is_empty() {
            out.push_str(format!("\n- Zip or postal code: {}", self.zip_or_postal_code).as_str());
        }
        if !self.city.is_empty() {
            out.push_str(format!("\n- City: {}", self.city).as_str());
        }
        if !self.state_or_province.is_empty() {
            out.push_str(format!("\n- State or province: {}", self.state_or_province).as_str());
        }
        if !self.country_or_region.is_empty() {
            out.push_str(format!("\n- Country or region: {}", self.country_or_region).as_str());
        }
        if !self.floor.is_empty() {
            out.push_str(format!("\n- Floor: {}", self.floor).as_str());
        }
        if !self.county.is_empty() {
            out.push_str(format!("\n- County: {}", self.county).as_str());
        }
        if !self.extra_address_details.is_empty() {
            out.push_str(
                format!(
                    "\n- Extra address details: {}",
                    self.extra_address_details
                        .iter()
                        .map(|d| format!("\n  - {}:{:#?}", d.name, d.content))
                        .collect::<String>()
                )
                .as_str(),
            );
        }
        if !self.social_security_number.is_empty() {
            out.push_str(format!("\n- Social security number: {}", self.social_security_number).as_str());
        }
        if !self.passport_number.is_empty() {
            out.push_str(format!("\n- Passport number: {}", self.passport_number).as_str());
        }
        if !self.license_number.is_empty() {
            out.push_str(format!("\n- License number: {}", self.license_number).as_str());
        }
        if !self.website.is_empty() {
            out.push_str(format!("\n- Website: {}", self.website).as_str());
        }
        if !self.x_handle.is_empty() {
            out.push_str(format!("\n - X handle: {}", self.x_handle).as_str());
        }
        if !self.second_phone_number.is_empty() {
            out.push_str(format!("\n - Second phone number: {}", self.second_phone_number).as_str());
        }
        if !self.linkedin.is_empty() {
            out.push_str(format!("\n - LinkedIn: {}", self.linkedin).as_str());
        }
        if !self.reddit.is_empty() {
            out.push_str(format!("\n - Reddit: {}", self.reddit).as_str());
        }
        if !self.facebook.is_empty() {
            out.push_str(format!("\n - Facebook: {}", self.facebook).as_str());
        }
        if !self.yahoo.is_empty() {
            out.push_str(format!("\n - Yahoo: {}", self.yahoo).as_str());
        }
        if !self.instagram.is_empty() {
            out.push_str(format!("\n - Instagram: {}", self.instagram).as_str());
        }
        if !self.company.is_empty() {
            out.push_str(format!("\n- Company: {}", self.company).as_str());
        }
        if !self.extra_contact_details.is_empty() {
            out.push_str(
                format!(
                    "\n- Extra contact details: {}",
                    self.extra_contact_details
                        .iter()
                        .map(|d| format!("\n  - {}:{:#?}", d.name, d.content))
                        .collect::<String>()
                )
                .as_str(),
            );
        }
        if !self.job_title.is_empty() {
            out.push_str(format!("\n- Job title: {}", self.job_title).as_str());
        }
        if !self.personal_website.is_empty() {
            out.push_str(format!("\n- Personal website: {}", self.personal_website).as_str());
        }
        if !self.work_phone_number.is_empty() {
            out.push_str(format!("\n- Work phone number: {}", self.work_phone_number).as_str());
        }
        if !self.work_email.is_empty() {
            out.push_str(format!("\n- Work email: {}", self.work_email).as_str());
        }
        if !self.extra_work_details.is_empty() {
            out.push_str(
                format!(
                    "\n- Extra work details: {}",
                    self.extra_work_details
                        .iter()
                        .map(|d| format!("\n  - {}:{:#?}", d.name, d.content))
                        .collect::<String>()
                )
                .as_str(),
            );
        }
        if !self.extra_sections.is_empty() {
            for section in self.extra_sections.iter() {
                out.push_str(format!("\n- Section: {}", section.section_name).as_str());
                for field in section.section_fields.iter() {
                    out.push_str(format!("\n  - {}: {:#?}", field.name, field.content).as_str());
                }
            }
        }

        out
    }
}

impl From<IdentityItem> for item_v1::ItemIdentity {
    fn from(value: IdentityItem) -> Self {
        item_v1::ItemIdentity {
            full_name: value.full_name,
            email: value.email,
            phone_number: value.phone_number,
            first_name: value.first_name,
            middle_name: value.middle_name,
            last_name: value.last_name,
            birthdate: value.birthdate,
            gender: value.gender,
            extra_personal_details: value
                .extra_personal_details
                .into_iter()
                .map(item_v1::ExtraField::from)
                .collect(),
            organization: value.organization,
            street_address: value.street_address,
            zip_or_postal_code: value.zip_or_postal_code,
            city: value.city,
            state_or_province: value.state_or_province,
            country_or_region: value.country_or_region,
            floor: value.floor,
            county: value.county,
            extra_address_details: value
                .extra_address_details
                .into_iter()
                .map(item_v1::ExtraField::from)
                .collect(),
            social_security_number: value.social_security_number,
            passport_number: value.passport_number,
            license_number: value.license_number,
            website: value.website,
            x_handle: value.x_handle,
            second_phone_number: value.second_phone_number,
            linkedin: value.linkedin,
            reddit: value.reddit,
            facebook: value.facebook,
            yahoo: value.yahoo,
            instagram: value.instagram,
            extra_contact_details: value
                .extra_contact_details
                .into_iter()
                .map(item_v1::ExtraField::from)
                .collect(),
            company: value.company,
            job_title: value.job_title,
            personal_website: value.personal_website,
            work_phone_number: value.work_phone_number,
            work_email: value.work_email,
            extra_work_details: value
                .extra_work_details
                .into_iter()
                .map(item_v1::ExtraField::from)
                .collect(),
            extra_sections: value
                .extra_sections
                .into_iter()
                .map(item_v1::CustomSection::from)
                .collect(),
            ..Default::default()
        }
    }
}

impl From<item_v1::ItemIdentity> for IdentityItem {
    fn from(value: item_v1::ItemIdentity) -> Self {
        Self {
            full_name: value.full_name,
            email: value.email,
            phone_number: value.phone_number,
            first_name: value.first_name,
            middle_name: value.middle_name,
            last_name: value.last_name,
            birthdate: value.birthdate,
            gender: value.gender,
            extra_personal_details: value
                .extra_personal_details
                .into_iter()
                .map(ItemExtraField::from)
                .collect(),
            organization: value.organization,
            street_address: value.street_address,
            zip_or_postal_code: value.zip_or_postal_code,
            city: value.city,
            state_or_province: value.state_or_province,
            country_or_region: value.country_or_region,
            floor: value.floor,
            county: value.county,
            extra_address_details: value
                .extra_address_details
                .into_iter()
                .map(ItemExtraField::from)
                .collect(),
            social_security_number: value.social_security_number,
            passport_number: value.passport_number,
            license_number: value.license_number,
            website: value.website,
            x_handle: value.x_handle,
            second_phone_number: value.second_phone_number,
            linkedin: value.linkedin,
            reddit: value.reddit,
            facebook: value.facebook,
            yahoo: value.yahoo,
            instagram: value.instagram,
            extra_contact_details: value
                .extra_contact_details
                .into_iter()
                .map(ItemExtraField::from)
                .collect(),
            company: value.company,
            job_title: value.job_title,
            personal_website: value.personal_website,
            work_phone_number: value.work_phone_number,
            work_email: value.work_email,
            extra_work_details: value.extra_work_details.into_iter().map(ItemExtraField::from).collect(),
            extra_sections: value.extra_sections.into_iter().map(CustomSection::from).collect(),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct SshKeyItem {
    pub private_key: String,
    pub public_key: String,
    pub sections: Vec<CustomSection>,
}

impl SshKeyItem {
    pub fn pretty_print(&self) -> String {
        let mut out = String::new();
        if !self.public_key.is_empty() {
            out.push_str(format!("\n- Public key: {}", self.public_key).as_str());
        }
        if !self.private_key.is_empty() {
            out.push_str(format!("\n- Private key:\n{}", self.private_key).as_str());
        }
        out
    }
}

impl From<SshKeyItem> for item_v1::ItemSSHKey {
    fn from(value: SshKeyItem) -> Self {
        item_v1::ItemSSHKey {
            private_key: value.private_key,
            public_key: value.public_key,
            sections: value.sections.into_iter().map(item_v1::CustomSection::from).collect(),
            ..Default::default()
        }
    }
}

impl From<item_v1::ItemSSHKey> for SshKeyItem {
    fn from(value: item_v1::ItemSSHKey) -> Self {
        Self {
            private_key: value.private_key,
            public_key: value.public_key,
            sections: value.sections.into_iter().map(CustomSection::from).collect(),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct WifiItem {
    pub ssid: String,
    pub password: String,
    pub security: WifiSecurity,
    pub sections: Vec<CustomSection>,
}

impl WifiItem {
    pub fn pretty_print(&self) -> String {
        let mut out = String::new();
        if !self.ssid.is_empty() {
            out.push_str(format!("\n- SSID: {}", self.ssid).as_str());
        }
        if !self.password.is_empty() {
            out.push_str(format!("\n- Password: {}", self.password).as_str());
        }
        if self.security != WifiSecurity::UnspecifiedWifiSecurity {
            out.push_str(format!("\n- Wifi Security: {:?}", self.security).as_str());
        }
        out
    }
}

impl From<WifiItem> for item_v1::ItemWifi {
    fn from(value: WifiItem) -> Self {
        item_v1::ItemWifi {
            ssid: value.ssid,
            password: value.password,
            security: item_v1::WifiSecurity::from(value.security).into(),
            sections: value.sections.into_iter().map(item_v1::CustomSection::from).collect(),
            ..Default::default()
        }
    }
}

impl From<item_v1::ItemWifi> for WifiItem {
    fn from(value: item_v1::ItemWifi) -> Self {
        Self {
            ssid: value.ssid,
            password: value.password,
            security: WifiSecurity::from(value.security.enum_value_or_default()),
            sections: value.sections.into_iter().map(CustomSection::from).collect(),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct CustomItem {
    pub sections: Vec<CustomSection>,
}

impl CustomItem {
    pub fn pretty_print(&self) -> String {
        let mut out = String::new();
        if !self.sections.is_empty() {
            for section in &self.sections {
                out.push_str(format!("\n- Section: {}", section.section_name).as_str());
                if !section.section_fields.is_empty() {
                    for field in &section.section_fields {
                        out.push_str(format!("\n  - {}: {:?}", field.name, field.content).as_str());
                    }
                }
            }
        }
        out
    }
}

impl From<CustomItem> for item_v1::ItemCustom {
    fn from(value: CustomItem) -> Self {
        item_v1::ItemCustom {
            sections: value.sections.into_iter().map(item_v1::CustomSection::from).collect(),
            ..Default::default()
        }
    }
}

impl From<item_v1::ItemCustom> for CustomItem {
    fn from(value: item_v1::ItemCustom) -> Self {
        Self {
            sections: value.sections.into_iter().map(CustomSection::from).collect(),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct CustomSection {
    pub section_name: String,
    pub section_fields: Vec<ItemExtraField>,
}

impl From<CustomSection> for item_v1::CustomSection {
    fn from(value: CustomSection) -> Self {
        item_v1::CustomSection {
            section_name: value.section_name,
            section_fields: value
                .section_fields
                .into_iter()
                .map(item_v1::ExtraField::from)
                .collect(),
            ..Default::default()
        }
    }
}

impl From<item_v1::CustomSection> for CustomSection {
    fn from(value: item_v1::CustomSection) -> Self {
        Self {
            section_name: value.section_name,
            section_fields: value.section_fields.into_iter().map(ItemExtraField::from).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub enum CardType {
    #[default]
    Unspecified,
    Other,
    Visa,
    Mastercard,
    AmericanExpress,
}

impl From<CardType> for item_v1::CardType {
    fn from(value: CardType) -> Self {
        match value {
            CardType::Unspecified => item_v1::CardType::Unspecified,
            CardType::Other => item_v1::CardType::Other,
            CardType::Visa => item_v1::CardType::Visa,
            CardType::Mastercard => item_v1::CardType::Mastercard,
            CardType::AmericanExpress => item_v1::CardType::AmericanExpress,
        }
    }
}

impl From<item_v1::CardType> for CardType {
    fn from(value: item_v1::CardType) -> Self {
        match value {
            item_v1::CardType::Unspecified => CardType::Unspecified,
            item_v1::CardType::Other => CardType::Other,
            item_v1::CardType::Visa => CardType::Visa,
            item_v1::CardType::Mastercard => CardType::Mastercard,
            item_v1::CardType::AmericanExpress => CardType::AmericanExpress,
        }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[proton_pass_derive::ffi_type(skip_serde_derive)]
pub enum WifiSecurity {
    #[default]
    UnspecifiedWifiSecurity,
    WPA,
    WPA2,
    WPA3,
    WEP,
}

impl From<WifiSecurity> for item_v1::WifiSecurity {
    fn from(value: WifiSecurity) -> Self {
        match value {
            WifiSecurity::UnspecifiedWifiSecurity => item_v1::WifiSecurity::UnspecifiedWifiSecurity,
            WifiSecurity::WPA => item_v1::WifiSecurity::WPA,
            WifiSecurity::WPA2 => item_v1::WifiSecurity::WPA2,
            WifiSecurity::WPA3 => item_v1::WifiSecurity::WPA3,
            WifiSecurity::WEP => item_v1::WifiSecurity::WEP,
        }
    }
}

impl From<item_v1::WifiSecurity> for WifiSecurity {
    fn from(value: item_v1::WifiSecurity) -> Self {
        match value {
            item_v1::WifiSecurity::UnspecifiedWifiSecurity => WifiSecurity::UnspecifiedWifiSecurity,
            item_v1::WifiSecurity::WPA => WifiSecurity::WPA,
            item_v1::WifiSecurity::WPA2 => WifiSecurity::WPA2,
            item_v1::WifiSecurity::WPA3 => WifiSecurity::WPA3,
            item_v1::WifiSecurity::WEP => WifiSecurity::WEP,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_item_data(content: ItemContent) -> ItemData {
        ItemData {
            title: "Test Item".to_string(),
            note: "Test note".to_string(),
            item_uuid: "test-uuid".to_string(),
            content,
            extra_fields: vec![],
            platform_specific: None,
        }
    }

    #[test]
    fn test_update_basic_fields() {
        let mut item = create_test_item_data(ItemContent::Note(NoteItem));

        // Update title
        let result = item.update_field("title", "New Title").unwrap();
        assert_eq!(result, UpdateFieldResult::FieldUpdated);
        assert_eq!(item.title, "New Title");

        // Update note (case insensitive)
        let result = item.update_field("NOTE", "New note").unwrap();
        assert_eq!(result, UpdateFieldResult::FieldUpdated);
        assert_eq!(item.note, "New note");
    }

    #[test]
    fn test_update_login_fields() {
        let mut item = create_test_item_data(ItemContent::Login(LoginItem {
            email: "old@example.com".to_string(),
            username: "olduser".to_string(),
            password: "oldpass".to_string(),
            urls: vec!["https://old.com".to_string()],
            totp_uri: "".to_string(),
            passkeys: vec![],
        }));

        // Update email
        assert_eq!(
            item.update_field("email", "new@example.com").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::Login(ref login) = item.content {
            assert_eq!(login.email, "new@example.com");
        } else {
            panic!("Expected Login content");
        }

        // Update username (case insensitive)
        assert_eq!(
            item.update_field("USERNAME", "newuser").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::Login(ref login) = item.content {
            assert_eq!(login.username, "newuser");
        } else {
            panic!("Expected Login content");
        }

        // Update password
        assert_eq!(
            item.update_field("password", "newpass").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::Login(ref login) = item.content {
            assert_eq!(login.password, "newpass");
        } else {
            panic!("Expected Login content");
        }

        // Update urls with comma-separated values
        assert_eq!(
            item.update_field("urls", "https://new1.com, https://new2.com,https://new3.com")
                .unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::Login(ref login) = item.content {
            assert_eq!(
                login.urls,
                vec!["https://new1.com", "https://new2.com", "https://new3.com"]
            );
        } else {
            panic!("Expected Login content");
        }
    }

    #[test]
    fn test_update_credit_card_fields() {
        let mut item = create_test_item_data(ItemContent::CreditCard(CreditCardItem {
            cardholder_name: "Old Name".to_string(),
            card_type: CardType::Visa,
            number: "1111".to_string(),
            verification_number: "111".to_string(),
            expiration_date: "01/25".to_string(),
            pin: "1111".to_string(),
        }));

        // Update cardholder_name
        assert_eq!(
            item.update_field("cardholder_name", "New Name").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::CreditCard(ref cc) = item.content {
            assert_eq!(cc.cardholder_name, "New Name");
        } else {
            panic!("Expected CreditCard content");
        }

        // Update number
        assert_eq!(
            item.update_field("number", "2222").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::CreditCard(ref cc) = item.content {
            assert_eq!(cc.number, "2222");
        } else {
            panic!("Expected CreditCard content");
        }

        // Update verification_number
        assert_eq!(
            item.update_field("verification_number", "222").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::CreditCard(ref cc) = item.content {
            assert_eq!(cc.verification_number, "222");
        } else {
            panic!("Expected CreditCard content");
        }

        // Update CVV (alias)
        assert_eq!(
            item.update_field("cvv", "333").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::CreditCard(ref cc) = item.content {
            assert_eq!(cc.verification_number, "333");
        } else {
            panic!("Expected CreditCard content");
        }

        // Update CVC (alias)
        assert_eq!(
            item.update_field("cvc", "444").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::CreditCard(ref cc) = item.content {
            assert_eq!(cc.verification_number, "444");
        } else {
            panic!("Expected CreditCard content");
        }

        // Update expiration_date
        assert_eq!(
            item.update_field("expiration_date", "12/30").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::CreditCard(ref cc) = item.content {
            assert_eq!(cc.expiration_date, "12/30");
        } else {
            panic!("Expected CreditCard content");
        }

        // Update pin
        assert_eq!(
            item.update_field("pin", "9999").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::CreditCard(ref cc) = item.content {
            assert_eq!(cc.pin, "9999");
        } else {
            panic!("Expected CreditCard content");
        }
    }

    #[test]
    fn test_update_identity_fields() {
        let mut item = create_test_item_data(ItemContent::Identity(Box::new(IdentityItem {
            full_name: "Old Name".to_string(),
            email: "old@example.com".to_string(),
            phone_number: "+1234567890".to_string(),
            first_name: "Old".to_string(),
            middle_name: "M".to_string(),
            last_name: "Name".to_string(),
            birthdate: "1990-01-01".to_string(),
            gender: "Male".to_string(),
            extra_personal_details: vec![],
            organization: "Old Org".to_string(),
            street_address: "123 Old St".to_string(),
            zip_or_postal_code: "12345".to_string(),
            city: "Old City".to_string(),
            state_or_province: "Old State".to_string(),
            country_or_region: "Old Country".to_string(),
            floor: String::new(),
            county: String::new(),
            extra_address_details: vec![],
            social_security_number: "111-11-1111".to_string(),
            passport_number: "A111111".to_string(),
            license_number: "L111111".to_string(),
            website: "https://old.com".to_string(),
            x_handle: String::new(),
            second_phone_number: String::new(),
            linkedin: String::new(),
            reddit: String::new(),
            facebook: String::new(),
            yahoo: String::new(),
            instagram: String::new(),
            extra_contact_details: vec![],
            company: "Old Company".to_string(),
            job_title: "Old Title".to_string(),
            personal_website: String::new(),
            work_phone_number: String::new(),
            work_email: String::new(),
            extra_work_details: vec![],
            extra_sections: vec![],
        })));

        // Test a few key fields
        assert_eq!(
            item.update_field("full_name", "New Name").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("email", "new@example.com").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("address", "456 New St").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("zip", "54321").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("state", "New State").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("country", "New Country").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("ssn", "222-22-2222").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("passport", "A222222").unwrap(),
            UpdateFieldResult::FieldUpdated
        );

        if let ItemContent::Identity(ref identity) = item.content {
            assert_eq!(identity.full_name, "New Name");
            assert_eq!(identity.email, "new@example.com");
            assert_eq!(identity.street_address, "456 New St");
            assert_eq!(identity.zip_or_postal_code, "54321");
            assert_eq!(identity.state_or_province, "New State");
            assert_eq!(identity.country_or_region, "New Country");
            assert_eq!(identity.social_security_number, "222-22-2222");
            assert_eq!(identity.passport_number, "A222222");
        } else {
            panic!("Expected Identity content");
        }
    }

    #[test]
    fn test_update_ssh_key_fields() {
        let mut item = create_test_item_data(ItemContent::SshKey(SshKeyItem {
            private_key: "old_private".to_string(),
            public_key: "old_public".to_string(),
            sections: vec![],
        }));

        assert_eq!(
            item.update_field("private_key", "new_private").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("public_key", "new_public").unwrap(),
            UpdateFieldResult::FieldUpdated
        );

        if let ItemContent::SshKey(ref ssh) = item.content {
            assert_eq!(ssh.private_key, "new_private");
            assert_eq!(ssh.public_key, "new_public");
        } else {
            panic!("Expected SshKey content");
        }
    }

    #[test]
    fn test_update_wifi_fields() {
        let mut item = create_test_item_data(ItemContent::Wifi(WifiItem {
            ssid: "OldNetwork".to_string(),
            password: "oldpass".to_string(),
            security: WifiSecurity::WPA2,
            sections: vec![],
        }));

        assert_eq!(
            item.update_field("ssid", "NewNetwork").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("password", "newpass").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("security", "WPA3").unwrap(),
            UpdateFieldResult::FieldUpdated
        );

        if let ItemContent::Wifi(ref wifi) = item.content {
            assert_eq!(wifi.ssid, "NewNetwork");
            assert_eq!(wifi.password, "newpass");
            assert_eq!(wifi.security, WifiSecurity::WPA3);
        } else {
            panic!("Expected Wifi content");
        }
    }

    #[test]
    fn test_update_custom_item_fields() {
        let mut item = create_test_item_data(ItemContent::Custom(CustomItem {
            sections: vec![
                CustomSection {
                    section_name: "Section 1".to_string(),
                    section_fields: vec![
                        ItemExtraField {
                            name: "field1".to_string(),
                            content: ItemExtraFieldContent::Text("old_value1".to_string()),
                        },
                        ItemExtraField {
                            name: "field2".to_string(),
                            content: ItemExtraFieldContent::Hidden("old_secret".to_string()),
                        },
                    ],
                },
                CustomSection {
                    section_name: "Section 2".to_string(),
                    section_fields: vec![ItemExtraField {
                        name: "field3".to_string(),
                        content: ItemExtraFieldContent::Text("old_value3".to_string()),
                    }],
                },
            ],
        }));

        // Update first matching field
        assert_eq!(
            item.update_field("field1", "new_value1").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("FIELD2", "new_secret").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("field3", "new_value3").unwrap(),
            UpdateFieldResult::FieldUpdated
        );

        if let ItemContent::Custom(ref custom) = item.content {
            assert_eq!(
                custom.sections[0].section_fields[0].content,
                ItemExtraFieldContent::Text("new_value1".to_string())
            );
            assert_eq!(
                custom.sections[0].section_fields[1].content,
                ItemExtraFieldContent::Hidden("new_secret".to_string())
            );
            assert_eq!(
                custom.sections[1].section_fields[0].content,
                ItemExtraFieldContent::Text("new_value3".to_string())
            );
        } else {
            panic!("Expected Custom content");
        }
    }

    #[test]
    fn test_update_extra_fields() {
        let mut item = create_test_item_data(ItemContent::Note(NoteItem));
        item.extra_fields = vec![
            ItemExtraField {
                name: "extra1".to_string(),
                content: ItemExtraFieldContent::Text("value1".to_string()),
            },
            ItemExtraField {
                name: "extra2".to_string(),
                content: ItemExtraFieldContent::Hidden("secret".to_string()),
            },
            ItemExtraField {
                name: "extra3".to_string(),
                content: ItemExtraFieldContent::Totp("otpauth://totp/test".to_string()),
            },
        ];

        // Update text field
        assert_eq!(
            item.update_field("extra1", "new_value1").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.extra_fields[0].content,
            ItemExtraFieldContent::Text("new_value1".to_string())
        );

        // Update hidden field (preserves type)
        assert_eq!(
            item.update_field("EXTRA2", "new_secret").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.extra_fields[1].content,
            ItemExtraFieldContent::Hidden("new_secret".to_string())
        );

        // Attempting to update totp field should fail
        let result = item.update_field("extra3", "otpauth://totp/new");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Editing TOTP fields is unsupported")
        );
    }

    #[test]
    fn test_update_timestamp_field_error() {
        let mut item = create_test_item_data(ItemContent::Note(NoteItem));
        item.extra_fields = vec![ItemExtraField {
            name: "timestamp_field".to_string(),
            content: ItemExtraFieldContent::Timestamp(1234567890),
        }];

        // Attempting to update a timestamp field should fail
        let result = item.update_field("timestamp_field", "new_value");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cannot update timestamp field")
        );
    }

    #[test]
    fn test_update_totp_field_error_in_login() {
        let mut item = create_test_item_data(ItemContent::Login(LoginItem {
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            password: "password".to_string(),
            urls: vec![],
            totp_uri: "otpauth://totp/test".to_string(),
            passkeys: vec![],
        }));

        // Attempting to update totp_uri should create a custom field instead (returns CustomFieldCreated)
        let result = item.update_field("totp_uri", "otpauth://totp/new").unwrap();
        assert_eq!(result, UpdateFieldResult::CustomFieldCreated);

        // The original totp_uri should be unchanged
        if let ItemContent::Login(ref login) = item.content {
            assert_eq!(login.totp_uri, "otpauth://totp/test");
        } else {
            panic!("Expected Login content");
        }

        // Same for totp alias
        let result = item.update_field("totp", "otpauth://totp/new2").unwrap();
        assert_eq!(result, UpdateFieldResult::CustomFieldCreated);
    }

    #[test]
    fn test_update_totp_field_error_in_custom_item() {
        let mut item = create_test_item_data(ItemContent::Custom(CustomItem {
            sections: vec![CustomSection {
                section_name: "Section 1".to_string(),
                section_fields: vec![
                    ItemExtraField {
                        name: "totp_field".to_string(),
                        content: ItemExtraFieldContent::Totp("otpauth://totp/test".to_string()),
                    },
                    ItemExtraField {
                        name: "text_field".to_string(),
                        content: ItemExtraFieldContent::Text("value".to_string()),
                    },
                ],
            }],
        }));

        // Attempting to update totp field in custom section should create a new custom field instead
        let result = item.update_field("totp_field", "otpauth://totp/new").unwrap();
        assert_eq!(result, UpdateFieldResult::CustomFieldCreated);

        // The original totp_field should be unchanged
        if let ItemContent::Custom(ref custom) = item.content {
            assert_eq!(
                custom.sections[0].section_fields[0].content,
                ItemExtraFieldContent::Totp("otpauth://totp/test".to_string())
            );
        } else {
            panic!("Expected Custom content");
        }
    }

    #[test]
    fn test_create_custom_field() {
        let mut item = create_test_item_data(ItemContent::Note(NoteItem));

        // Non-existent field should create a new custom field
        assert_eq!(
            item.update_field("new_custom_field", "custom_value").unwrap(),
            UpdateFieldResult::CustomFieldCreated
        );
        assert_eq!(item.extra_fields.len(), 1);
        assert_eq!(item.extra_fields[0].name, "new_custom_field");
        assert_eq!(
            item.extra_fields[0].content,
            ItemExtraFieldContent::Text("custom_value".to_string())
        );
    }

    #[test]
    fn test_case_insensitive_matching() {
        let mut item = create_test_item_data(ItemContent::Login(LoginItem {
            email: "old@example.com".to_string(),
            username: "olduser".to_string(),
            password: "oldpass".to_string(),
            urls: vec![],
            totp_uri: "".to_string(),
            passkeys: vec![],
        }));

        // Test case insensitive matching
        assert_eq!(
            item.update_field("EMAIL", "new@example.com").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("UserName", "newuser").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("PASSWORD", "newpass").unwrap(),
            UpdateFieldResult::FieldUpdated
        );

        if let ItemContent::Login(ref login) = item.content {
            assert_eq!(login.email, "new@example.com");
            assert_eq!(login.username, "newuser");
            assert_eq!(login.password, "newpass");
        } else {
            panic!("Expected Login content");
        }
    }

    #[test]
    fn test_field_aliases() {
        let mut item = create_test_item_data(ItemContent::Identity(Box::new(IdentityItem {
            full_name: "".to_string(),
            email: "".to_string(),
            phone_number: "".to_string(),
            first_name: "".to_string(),
            middle_name: "".to_string(),
            last_name: "".to_string(),
            birthdate: "".to_string(),
            gender: "".to_string(),
            extra_personal_details: vec![],
            organization: "".to_string(),
            street_address: "".to_string(),
            zip_or_postal_code: "".to_string(),
            city: "".to_string(),
            state_or_province: "".to_string(),
            country_or_region: "".to_string(),
            floor: String::new(),
            county: String::new(),
            extra_address_details: vec![],
            social_security_number: "".to_string(),
            passport_number: "".to_string(),
            license_number: "".to_string(),
            website: "".to_string(),
            x_handle: String::new(),
            second_phone_number: String::new(),
            linkedin: String::new(),
            reddit: String::new(),
            facebook: String::new(),
            yahoo: String::new(),
            instagram: String::new(),
            extra_contact_details: vec![],
            company: "".to_string(),
            job_title: "".to_string(),
            personal_website: String::new(),
            work_phone_number: String::new(),
            work_email: String::new(),
            extra_work_details: vec![],
            extra_sections: vec![],
        })));

        // Test various field aliases work
        assert_eq!(
            item.update_field("address", "123 Main St").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("zip", "12345").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("postal_code", "54321").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("state", "CA").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("province", "ON").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("country", "USA").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("region", "Americas").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("ssn", "123-45-6789").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        assert_eq!(
            item.update_field("passport", "A1234567").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
    }

    #[test]
    fn test_empty_urls_parsing() {
        let mut item = create_test_item_data(ItemContent::Login(LoginItem {
            email: "".to_string(),
            username: "".to_string(),
            password: "".to_string(),
            urls: vec!["https://old.com".to_string()],
            totp_uri: "".to_string(),
            passkeys: vec![],
        }));

        // Empty string should result in empty urls vector
        assert_eq!(item.update_field("urls", "").unwrap(), UpdateFieldResult::FieldUpdated);
        if let ItemContent::Login(ref login) = item.content {
            assert!(login.urls.is_empty());
        } else {
            panic!("Expected Login content");
        }

        // Whitespace-only values should be filtered out
        assert_eq!(
            item.update_field("urls", "  ,  , ").unwrap(),
            UpdateFieldResult::FieldUpdated
        );
        if let ItemContent::Login(ref login) = item.content {
            assert!(login.urls.is_empty());
        } else {
            panic!("Expected Login content");
        }
    }

    #[test]
    fn test_perform_update_does_not_duplicate_custom_fields() {
        // Create an ItemData with CustomItem containing some fields
        let original_item = create_test_item_data(ItemContent::Custom(CustomItem {
            sections: vec![CustomSection {
                section_name: "Test Section".to_string(),
                section_fields: vec![
                    ItemExtraField {
                        name: "field1".to_string(),
                        content: ItemExtraFieldContent::Text("original_value1".to_string()),
                    },
                    ItemExtraField {
                        name: "field2".to_string(),
                        content: ItemExtraFieldContent::Hidden("original_secret".to_string()),
                    },
                ],
            }],
        }));

        // Serialize the original
        let original_bytes = original_item.clone().serialize().unwrap();

        // Update one of the custom fields
        let mut updated_item = original_item.clone();
        let result = updated_item.update_field("field1", "new_value1").unwrap();
        assert_eq!(result, UpdateFieldResult::FieldUpdated);

        // Perform the update using the perform_update method
        let updated_bytes = ItemData::perform_update(&original_bytes, &updated_item).unwrap();

        // Deserialize the result
        let final_item = ItemData::deserialize(&updated_bytes).unwrap();

        // Verify that fields are not duplicated
        if let ItemContent::Custom(ref custom) = final_item.content {
            assert_eq!(custom.sections.len(), 1, "Should have exactly 1 section");
            assert_eq!(
                custom.sections[0].section_fields.len(),
                2,
                "Should have exactly 2 fields, not duplicated"
            );

            // Verify the values
            assert_eq!(custom.sections[0].section_fields[0].name, "field1");
            assert_eq!(
                custom.sections[0].section_fields[0].content,
                ItemExtraFieldContent::Text("new_value1".to_string())
            );
            assert_eq!(custom.sections[0].section_fields[1].name, "field2");
            assert_eq!(
                custom.sections[0].section_fields[1].content,
                ItemExtraFieldContent::Hidden("original_secret".to_string())
            );
        } else {
            panic!("Expected Custom content");
        }
    }

    #[test]
    fn test_perform_update_does_not_duplicate_extra_fields() {
        // Create an ItemData with extra fields
        let mut original_item = create_test_item_data(ItemContent::Note(NoteItem));
        original_item.extra_fields = vec![
            ItemExtraField {
                name: "extra1".to_string(),
                content: ItemExtraFieldContent::Text("value1".to_string()),
            },
            ItemExtraField {
                name: "extra2".to_string(),
                content: ItemExtraFieldContent::Hidden("secret".to_string()),
            },
        ];

        // Serialize the original
        let original_bytes = original_item.clone().serialize().unwrap();

        // Update one of the extra fields
        let mut updated_item = original_item.clone();
        let result = updated_item.update_field("extra1", "new_value1").unwrap();
        assert_eq!(result, UpdateFieldResult::FieldUpdated);

        // Perform the update using the perform_update method
        let updated_bytes = ItemData::perform_update(&original_bytes, &updated_item).unwrap();

        // Deserialize the result
        let final_item = ItemData::deserialize(&updated_bytes).unwrap();

        // Verify that extra fields are not duplicated
        assert_eq!(
            final_item.extra_fields.len(),
            2,
            "Should have exactly 2 extra fields, not duplicated"
        );

        // Verify the values
        assert_eq!(final_item.extra_fields[0].name, "extra1");
        assert_eq!(
            final_item.extra_fields[0].content,
            ItemExtraFieldContent::Text("new_value1".to_string())
        );
        assert_eq!(final_item.extra_fields[1].name, "extra2");
        assert_eq!(
            final_item.extra_fields[1].content,
            ItemExtraFieldContent::Hidden("secret".to_string())
        );
    }

    #[test]
    fn test_perform_update_does_not_duplicate_login_urls() {
        // Create an ItemData with login containing URLs
        let original_item = create_test_item_data(ItemContent::Login(LoginItem {
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            password: "password123".to_string(),
            urls: vec!["https://example.com".to_string(), "https://app.example.com".to_string()],
            totp_uri: "".to_string(),
            passkeys: vec![],
        }));

        // Serialize the original
        let original_bytes = original_item.clone().serialize().unwrap();

        // Update the URLs
        let mut updated_item = original_item.clone();
        let result = updated_item
            .update_field("urls", "https://new1.example.com, https://new2.example.com")
            .unwrap();
        assert_eq!(result, UpdateFieldResult::FieldUpdated);

        // Perform the update using the perform_update method
        let updated_bytes = ItemData::perform_update(&original_bytes, &updated_item).unwrap();

        // Deserialize the result
        let final_item = ItemData::deserialize(&updated_bytes).unwrap();

        // Verify that URLs are not duplicated
        if let ItemContent::Login(login) = final_item.content {
            assert_eq!(login.urls.len(), 2, "Should have exactly 2 URLs, not duplicated");
            assert_eq!(login.urls[0], "https://new1.example.com");
            assert_eq!(login.urls[1], "https://new2.example.com");
        } else {
            panic!("Expected Login content");
        }
    }
}
