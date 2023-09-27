use std::str::FromStr;
use serde_json::{Map, Value};

pub type Queries = Map<String, Value>;

pub trait GetQueryValue {
    fn get_string_value(&self, key: &str) -> Option<String>;
    fn get_string_parsable_value<T: FromStr>(&self, key: &str) -> Option<T>;
}

impl GetQueryValue for Queries {
    fn get_string_value(&self, key: &str) -> Option<String> {
        if self.contains_key(key) {
            match self[key].as_str() {
                Some(value) => Some(value.to_string()),
                _ => None
            }
        } else {
            None
        }
    }

    fn get_string_parsable_value<T: FromStr>(&self, key: &str) -> Option<T> {
        match Self::get_string_value(self, key) {
            Some(value) => {
                match value.parse::<T>() {
                    Ok(parsed) => Some(parsed),
                    _ => None
                }
            },
            _ => None
        }
    }
}