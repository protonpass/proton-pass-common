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

#[macro_export]
macro_rules! display_for_basic {
    ($t:ty) => {
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

#[macro_export]
macro_rules! assert_enum_variant {
    ($v:expr, $p:path) => {
        assert_enum_variant!($v, $p, "");
    };
    ($v:expr, $p:path, $($msg:tt)+) => {
        match &$v {
            $p { .. } => (),
            _ => panic!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{}`: {}"#, &$v, stringify!($p), format_args!($($msg)+)),
        }
    };
}

#[macro_export]
macro_rules! assert_false {
    ($val:expr) => {
        assert_false!($val, "");
    };
    ($val:expr, $($msg:tt)+) => {
        assert_eq!($val, false, "{}", format_args!($($msg)+));
    }
}

#[macro_export]
macro_rules! assert_true {
    ($val:expr) => {
        assert_true!($val, "Value should be true");
    };
    ($val:expr, $($msg:tt)+) => {
        assert!($val, "{}", format_args!($($msg)+));
    }
}
