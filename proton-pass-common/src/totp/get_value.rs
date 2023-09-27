use serde_json::{Map, Value};
use std::str::FromStr;

pub type Queries = Map<String, Value>;

pub trait GetQueryValue {
    fn get_string_value(&self, key: &str) -> Option<String>;
    fn get_string_parsable_value<T: FromStr>(&self, key: &str) -> Option<T>;
}

impl GetQueryValue for Queries {
    fn get_string_value(&self, key: &str) -> Option<String> {
        if self.contains_key(key) {
            self[key].as_str().map(|value| value.to_string())
        } else {
            None
        }
    }

    fn get_string_parsable_value<T: FromStr>(&self, key: &str) -> Option<T> {
        match Self::get_string_value(self, key) {
            Some(value) => match value.parse::<T>() {
                Ok(parsed) => Some(parsed),
                _ => None,
            },
            _ => None,
        }
    }
}
