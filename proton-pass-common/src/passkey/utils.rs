use serde_json::Value;
use std::collections::BTreeMap;

pub fn transform_byte_array(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            // Check if all keys are numeric strings and all values are i8 fitting in u8
            let mut is_numeric_map = true;
            let mut temp: BTreeMap<usize, u8> = BTreeMap::new();

            for (k, v) in &map {
                if let Ok(index) = k.parse::<usize>() {
                    if let Some(num) = v.as_i64().and_then(|n| {
                        if n >= i8::MIN as i64 && n <= i8::MAX as i64 {
                            Some((n as i8) as u8)
                        } else if n >= u8::MIN as i64 && n <= u8::MAX as i64 {
                            Some(n as u8)
                        } else {
                            None
                        }
                    }) {
                        temp.insert(index, num);
                    } else {
                        is_numeric_map = false;
                        break;
                    }
                } else {
                    is_numeric_map = false;
                    break;
                }
            }

            if is_numeric_map {
                // Collect values in order of keys
                let array: Vec<Value> = temp.values().cloned().map(Value::from).collect();
                Value::Array(array)
            } else {
                // Recursively transform each value
                let transformed_map = map.into_iter().map(|(k, v)| (k, transform_byte_array(v))).collect();
                Value::Object(transformed_map)
            }
        }
        Value::Array(arr) => {
            // Recursively transform each element in the array
            Value::Array(arr.into_iter().map(transform_byte_array).collect())
        }
        other => other,
    }
}

pub fn set_user_display_name_if_empty(obj: &mut serde_json::Map<String, Value>) -> bool {
    if let Some(user_obj) = obj.get("user") {
        return match (user_obj.get("name"), user_obj.get("displayName")) {
            (Some(Value::String(name)), Some(Value::Null)) => {
                // Prepare user object with a set displayName
                let mut user_obj_clone = user_obj.clone();
                match user_obj_clone.as_object_mut() {
                    Some(m) => {
                        m.insert("displayName".to_string(), Value::String(name.to_string()));
                    }
                    None => return false,
                };

                // Insert user object to root Json object
                obj.insert("user".to_string(), user_obj_clone);

                true
            }
            _ => false,
        };
    }

    false
}
