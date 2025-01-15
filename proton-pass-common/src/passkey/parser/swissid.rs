use super::PasskeySanitizer;
use serde_json::Value;
use std::collections::BTreeMap;

/// swissid.ch has the following special cases:
// /// 1. Sends the byte arrays as dictionaries with indices as keys instead of byte arrays
pub struct SwissIdSanitizer;

impl SwissIdSanitizer {
    fn transform(value: Value) -> Value {
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
                    let transformed_map = map.into_iter().map(|(k, v)| (k, Self::transform(v))).collect();
                    Value::Object(transformed_map)
                }
            }
            Value::Array(arr) => {
                // Recursively transform each element in the array
                Value::Array(arr.into_iter().map(Self::transform).collect())
            }
            other => other,
        }
    }
}

impl PasskeySanitizer for SwissIdSanitizer {
    fn should_sanitize(&self, url: Option<&str>, request: &str) -> bool {
        let url_matches = url.is_some_and(|u| u.contains("swissid.ch"));
        url_matches || request.contains("swissid.ch")
    }

    fn sanitize(&self, request: &str) -> String {
        let parsed: Value = match serde_json::from_str(request) {
            Ok(v) => v,
            Err(_) => return request.to_string(),
        };

        let transformed = Self::transform(parsed);
        serde_json::to_string(&transformed).unwrap_or(request.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_web_request() {
        let input = r#"
        {"challenge":{"0":103,"1":-58,"2":-87,"3":-100,"4":-24,"5":102,"6":39,"7":-80,"8":91,"9":-105,"10":-100,"11":32,"12":1,"13":-92,"14":-100,"15":-8,"16":-48,"17":34,"18":36,"19":102,"20":110,"21":-28,"22":14,"23":-72,"24":-52,"25":-31,"26":56,"27":-32,"28":-34,"29":75,"30":51,"31":-74},"rp":{"name":"login.swissid.ch"},"user":{"id":{"0":89,"1":15,"2":28,"3":30,"4":41,"5":52,"6":64,"7":73,"8":85,"9":97,"10":101,"11":113,"12":121,"13":115,"14":52,"15":51,"16":52,"17":102,"18":45,"19":56,"20":56,"21":57,"22":54,"23":45,"24":53,"25":52,"26":57,"27":102,"28":50,"29":55,"30":97,"31":98,"32":56,"33":98,"34":56,"35":48},"name":"test@email.com","displayName":"test@email.com"},"pubKeyCredParams":[{"type":"public-key","alg":-257},{"type":"public-key","alg":-7}],"attestation":"indirect","timeout":60000,"authenticatorSelection":{"userVerification":"required","authenticatorAttachment":"platform","requireResidentKey":false}}
        "#.trim();
        let expected = r#"
        {"challenge":[103,198,169,156,232,102,39,176,91,151,156,32,1,164,156,248,208,34,36,102,110,228,14,184,204,225,56,224,222,75,51,182],"rp":{"name":"login.swissid.ch"},"user":{"id":[89,15,28,30,41,52,64,73,85,97,101,113,121,115,52,51,52,102,45,56,56,57,54,45,53,52,57,102,50,55,97,98,56,98,56,48],"name":"test@email.com","displayName":"test@email.com"},"pubKeyCredParams":[{"type":"public-key","alg":-257},{"type":"public-key","alg":-7}],"attestation":"indirect","timeout":60000,"authenticatorSelection":{"userVerification":"required","authenticatorAttachment":"platform","requireResidentKey":false}}
        "#.trim();

        let res = SwissIdSanitizer.sanitize(input);
        assert_eq!(expected, res);
    }
}
