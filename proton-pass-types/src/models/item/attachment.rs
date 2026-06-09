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

use crate::protos::file::file_v1;
use anyhow::{Context, Result};

#[derive(Clone, Debug, serde::Serialize)]
pub struct AttachmentId(pub(crate) String);
display_for_basic!(AttachmentId);

impl AttachmentId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AttachmentChunk {
    pub chunk_id: String,
    pub index: usize,
    pub size: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ItemAttachment {
    pub id: AttachmentId,
    pub size: u64,
    pub encryption_version: u8,
    pub content: ItemAttachmentContent,
    pub chunks: Vec<AttachmentChunk>,
    pub encrypted_file_key: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ItemAttachmentContent {
    pub name: String,
    pub mime_type: String,
}

impl ItemAttachmentContent {
    pub fn serialize(self) -> Result<Vec<u8>> {
        let as_proto = file_v1::FileMetadata::from(self);
        as_proto.to_vec().context("Error serializing FileMetadata to proto")
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let as_proto =
            file_v1::FileMetadata::decode_from_slice(data).context("Error decoding FileMetadata from proto")?;
        Ok(Self::from(as_proto))
    }
}

impl From<file_v1::FileMetadata> for ItemAttachmentContent {
    fn from(file_metadata: file_v1::FileMetadata) -> Self {
        Self {
            name: file_metadata.name,
            mime_type: file_metadata.mime_type,
        }
    }
}

impl From<ItemAttachmentContent> for file_v1::FileMetadata {
    fn from(attachment: ItemAttachmentContent) -> Self {
        Self {
            name: attachment.name,
            mime_type: attachment.mime_type,
            ..Default::default()
        }
    }
}
