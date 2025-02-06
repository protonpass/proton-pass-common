// Extracted and adapted from
// https://github.com/magiclen/passwords/blob/ec18bb837a8acc75fcee638d8e1d17f96d41fbf4/src/analyzer/mod.rs
//
// MIT License
//
// Copyright (c) 2018 magiclen.org (Ron Li)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzedPassword {
    password: String,
    length: usize,
    spaces_count: usize,
    numbers_count: usize,
    lowercase_letters_count: usize,
    uppercase_letters_count: usize,
    symbols_count: usize,
    other_characters_count: usize,
    consecutive_count: usize,
    non_consecutive_count: usize,
    progressive_count: usize,
}

impl AnalyzedPassword {
    pub fn length(&self) -> usize {
        self.length
    }

    pub fn spaces_count(&self) -> usize {
        self.spaces_count
    }

    pub fn numbers_count(&self) -> usize {
        self.numbers_count
    }

    pub fn lowercase_letters_count(&self) -> usize {
        self.lowercase_letters_count
    }

    pub fn uppercase_letters_count(&self) -> usize {
        self.uppercase_letters_count
    }

    pub fn symbols_count(&self) -> usize {
        self.symbols_count
    }

    pub fn other_characters_count(&self) -> usize {
        self.other_characters_count
    }

    pub fn consecutive_count(&self) -> usize {
        self.consecutive_count
    }

    pub fn non_consecutive_count(&self) -> usize {
        self.non_consecutive_count
    }

    pub fn progressive_count(&self) -> usize {
        self.progressive_count
    }
}

/// Analyze a password.
pub fn analyze<S: AsRef<str>>(password: S) -> AnalyzedPassword {
    let password = password.as_ref();
    let password_chars = password.chars();

    let mut spaces_count = 0usize;
    let mut numbers_count = 0usize;
    let mut lowercase_letters_count = 0usize;
    let mut uppercase_letters_count = 0usize;
    let mut symbols_count = 0usize;
    let mut other_characters_count = 0usize;
    let mut consecutive_count = 0usize;
    let mut non_consecutive_count = 0usize;
    let mut progressive_count = 0usize;

    let mut last_char_code = u32::MAX;
    let mut last_step = i32::MAX;
    let mut last_step_consecutive = false;
    let mut last_step_repeat = false;
    let mut last_char_code_consecutive = false;

    let mut count_map: HashMap<char, usize> = HashMap::new();

    let mut password = String::with_capacity(password.len());

    let mut length = 0;

    for c in password_chars {
        let char_code = c as u32;

        if char_code <= 0x1F || char_code == 0x7F {
            continue;
        }

        password.push(c);

        length += 1;

        let count = count_map.entry(c).or_insert(0);
        *count += 1;

        if last_char_code == char_code {
            if last_char_code_consecutive {
                consecutive_count += 1;
            } else {
                consecutive_count += 2;
                last_char_code_consecutive = true;
            }
            last_step_consecutive = false;
        } else {
            last_char_code_consecutive = false;
            let step = last_char_code as i32 - char_code as i32;
            last_char_code = char_code;
            if last_step == step {
                if last_step_consecutive {
                    progressive_count += 1;
                } else {
                    last_step_consecutive = true;
                    if last_step_repeat {
                        progressive_count += 2;
                    } else {
                        progressive_count += 3;
                    }
                    last_step_repeat = true;
                }
            } else {
                last_step = step;
                if last_step_consecutive {
                    last_step_consecutive = false;
                } else {
                    last_step_repeat = false;
                }
            }
        }
        if (48..=57).contains(&char_code) {
            numbers_count += 1;
        } else if (65..=90).contains(&char_code) {
            uppercase_letters_count += 1;
        } else if (97..=122).contains(&char_code) {
            lowercase_letters_count += 1;
        } else if char_code == 32 {
            spaces_count += 1;
        } else if (33..=47).contains(&char_code)
            || (58..=64).contains(&char_code)
            || (91..=96).contains(&char_code)
            || (123..=126).contains(&char_code)
        {
            symbols_count += 1;
        } else {
            other_characters_count += 1;
        }
    }

    for (_, &a) in count_map.iter() {
        if a > 1 {
            non_consecutive_count += a;
        }
    }

    non_consecutive_count -= consecutive_count;

    AnalyzedPassword {
        password,
        length,
        spaces_count,
        numbers_count,
        lowercase_letters_count,
        uppercase_letters_count,
        symbols_count,
        other_characters_count,
        consecutive_count,
        non_consecutive_count,
        progressive_count,
    }
}
