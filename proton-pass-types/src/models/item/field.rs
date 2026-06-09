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

use crate::{ItemExtraField, ItemExtraFieldContent};

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
