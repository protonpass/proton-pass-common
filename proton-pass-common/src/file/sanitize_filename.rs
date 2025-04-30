// Extracted from https://github.com/kardeiz/sanitize-filename/blob/9428a9485243e0ab45206246e8fa1e9d42256d8a/src/lib.rs
// Replaced regex with regex_lite
//
// MIT License
// Copyright (c) 2024 Sanitize Filename contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
use std::sync::OnceLock;

use regex_lite::{Regex, RegexBuilder};

static ILLEGAL_RE: OnceLock<Regex> = OnceLock::new();
static CONTROL_RE: OnceLock<Regex> = OnceLock::new();
static RESERVED_RE: OnceLock<Regex> = OnceLock::new();
static WINDOWS_RESERVED_RE: OnceLock<Regex> = OnceLock::new();
static WINDOWS_TRAILING_RE: OnceLock<Regex> = OnceLock::new();

fn illegal_re() -> &'static Regex {
    ILLEGAL_RE.get_or_init(|| Regex::new(r#"[/\?<>\\:\*\|":]"#).unwrap())
}

fn control_re() -> &'static Regex {
    CONTROL_RE.get_or_init(|| Regex::new(r#"[\x00-\x1f\x80-\x9f]"#).unwrap())
}

fn reserved_re() -> &'static Regex {
    RESERVED_RE.get_or_init(|| Regex::new(r#"^\.+$"#).unwrap())
}

fn windows_reserved_re() -> &'static Regex {
    WINDOWS_RESERVED_RE.get_or_init(|| {
        RegexBuilder::new(r#"(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$"#)
            .case_insensitive(true)
            .build()
            .unwrap()
    })
}

fn windows_trailing_re() -> &'static Regex {
    WINDOWS_TRAILING_RE.get_or_init(|| Regex::new(r#"[\. ]+$"#).unwrap())
}

#[derive(Clone)]
pub struct Options<'a> {
    pub windows: bool,
    pub truncate: bool,
    pub replacement: &'a str,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            windows: cfg!(windows),
            truncate: true,
            replacement: "",
        }
    }
}

pub fn sanitize<S: AsRef<str>>(name: S) -> String {
    sanitize_with_options(name, Options::default())
}

pub fn sanitize_with_options<S: AsRef<str>>(name: S, options: Options) -> String {
    let Options {
        windows,
        truncate,
        replacement,
    } = options;
    let name = name.as_ref();

    let name = illegal_re().replace_all(name, replacement);
    let name = control_re().replace_all(&name, replacement);
    let name = reserved_re().replace(&name, replacement);

    let collect = |name: ::std::borrow::Cow<str>| {
        if truncate && name.len() > 255 {
            let mut end = 255;
            loop {
                if name.is_char_boundary(end) {
                    break;
                }
                end -= 1;
            }
            String::from(&name[..end])
        } else {
            String::from(name)
        }
    };

    if windows {
        let name = windows_reserved_re().replace(&name, replacement);
        let name = windows_trailing_re().replace(&name, replacement);
        collect(name)
    } else {
        collect(name)
    }
}

#[derive(Clone)]
pub struct OptionsForCheck {
    pub windows: bool,
    pub truncate: bool,
}

impl Default for OptionsForCheck {
    fn default() -> Self {
        OptionsForCheck {
            windows: cfg!(windows),
            truncate: true,
        }
    }
}

pub fn is_sanitized<S: AsRef<str>>(name: S) -> bool {
    is_sanitized_with_options(name, OptionsForCheck::default())
}

pub fn is_sanitized_with_options<S: AsRef<str>>(name: S, options: OptionsForCheck) -> bool {
    let OptionsForCheck { windows, truncate } = options;
    let name = name.as_ref();

    if illegal_re().is_match(name) {
        return false;
    }
    if control_re().is_match(name) {
        return false;
    }
    if reserved_re().is_match(name) {
        return false;
    }
    if truncate && name.len() > 255 {
        return false;
    }
    if windows {
        if windows_reserved_re().is_match(name) {
            return false;
        }
        if windows_trailing_re().is_match(name) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {

    // From https://github.com/parshap/node-sanitize-filename/blob/master/test.js
    static NAMES: &[&str] = &[
        "the quick brown fox jumped over the lazy dog",
        "résumé",
        "hello\u{0000}world",
        "hello\nworld",
        "semi;colon.js",
        ";leading-semi.js",
        "slash\\.js",
        "slash/.js",
        "col:on.js",
        "star*.js",
        "question?.js",
        "quote\".js",
        "singlequote'.js",
        "brack<e>ts.js",
        "p|pes.js",
        "plus+.js",
        "'five and six<seven'.js",
        " space at front",
        "space at end ",
        ".period",
        "period.",
        "relative/path/to/some/dir",
        "/abs/path/to/some/dir",
        "~/.\u{0000}notssh/authorized_keys",
        "",
        "h?w",
        "h/w",
        "h*w",
        ".",
        "..",
        "./",
        "../",
        "/..",
        "/../",
        "*.|.",
        "./",
        "./foobar",
        "../foobar",
        "../../foobar",
        "./././foobar",
        "|*.what",
        "LPT9.asdf",
        "foobar...",
    ];

    static NAMES_CLEANED: &[&str] = &[
        "the quick brown fox jumped over the lazy dog",
        "résumé",
        "helloworld",
        "helloworld",
        "semi;colon.js",
        ";leading-semi.js",
        "slash.js",
        "slash.js",
        "colon.js",
        "star.js",
        "question.js",
        "quote.js",
        "singlequote'.js",
        "brackets.js",
        "ppes.js",
        "plus+.js",
        "'five and sixseven'.js",
        " space at front",
        "space at end",
        ".period",
        "period",
        "relativepathtosomedir",
        "abspathtosomedir",
        "~.notsshauthorized_keys",
        "",
        "hw",
        "hw",
        "hw",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        ".foobar",
        "..foobar",
        "....foobar",
        "...foobar",
        ".what",
        "",
        "foobar",
    ];

    static NAMES_IS_SANITIZED: &[bool] = &[
        true, true, false, false, true, true, false, false, false, false, false, false, true, false, false, true,
        false, true, false, true, false, false, false, false, true, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false,
    ];

    #[test]
    fn it_works() {
        // sanitize
        let options = super::Options {
            windows: true,
            truncate: true,
            replacement: "",
        };

        for (idx, name) in NAMES.iter().enumerate() {
            assert_eq!(super::sanitize_with_options(name, options.clone()), NAMES_CLEANED[idx]);
        }

        let long = "a".repeat(300);
        let shorter = "a".repeat(255);
        assert_eq!(super::sanitize_with_options(long, options.clone()), shorter);

        // is_sanitized
        let options = super::OptionsForCheck {
            windows: true,
            truncate: true,
        };

        for (idx, name) in NAMES.iter().enumerate() {
            assert_eq!(
                super::is_sanitized_with_options(name, options.clone()),
                NAMES_IS_SANITIZED[idx]
            );
        }

        let long = "a".repeat(300);
        assert!(!super::is_sanitized_with_options(long, options.clone()));
    }
}
