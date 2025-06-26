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
