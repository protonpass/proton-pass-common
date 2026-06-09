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

#![allow(unexpected_cfgs)]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[macro_use]
mod macros;

mod models;
mod protos;

macro_rules! implement_custom_methods {
    ($t:ty) => {
        impl $t {
            pub fn to_vec(&self) -> Result<Vec<u8>, protobuf::Error> {
                use protobuf::Message;

                let mut res = Vec::new();
                self.write_to_vec(&mut res)?;
                Ok(res)
            }

            pub fn decode_from_vec(source: Vec<u8>) -> Result<Self, protobuf::Error> {
                Self::decode_from_slice(&source)
            }

            pub fn decode_from_slice(source: &[u8]) -> Result<Self, protobuf::Error> {
                use protobuf::Message;

                Self::parse_from_bytes(source)
            }
        }

        impl Eq for $t {}
    };
}

pub use models::item::*;
pub use protobuf;

implement_custom_methods!(protos::item::item_v1::Item);
implement_custom_methods!(protos::file::file_v1::FileMetadata);
