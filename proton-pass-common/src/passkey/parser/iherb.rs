use super::PasskeySanitizer;
use serde_json::Value;

/// iHerb has the following special cases:
/// 1. Can send a null displayName in the user object. We will copy the name if present.
pub struct IherbSanitizer;

impl PasskeySanitizer for IherbSanitizer {
    fn should_sanitize(&self, url: Option<&str>, request: &str) -> bool {
        let url_matches = url.is_some_and(|u| u.contains("iherb.com"));
        url_matches || request.contains("iherb.com")
    }

    fn sanitize(&self, request: &str) -> String {
        let parsed: Value = match serde_json::from_str(request) {
            Ok(v) => v,
            Err(_) => return request.to_string(),
        };
        let mut obj = match parsed {
            Value::Object(o) => o,
            _ => return request.to_string(),
        };

        if let Some(user_obj) = obj.get("user") {
            return match (user_obj.get("name"), user_obj.get("displayName")) {
                (Some(Value::String(name)), Some(Value::Null)) => {
                    // Prepare user object with a set displayName
                    let mut user_obj_clone = user_obj.clone();
                    match user_obj_clone.as_object_mut() {
                        Some(m) => {
                            m.insert("displayName".to_string(), Value::String(name.to_string()));
                        }
                        None => return request.to_string(),
                    };

                    // Insert user object to root Json object
                    obj.insert("user".to_string(), user_obj_clone);

                    serde_json::to_string(&Value::Object(obj)).unwrap_or(request.to_string())
                }
                _ => request.to_string(),
            };
        }

        request.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_request() {
        let input = r#"
        {
            "rp": {
                "id": "iherb.com",
                "name": "iHerb"
            },
            "user": {
                "name": "justatest@user.com",
                "id": "pk1Ihk+Ww0uLcaQhKpi6Qg==",
                "displayName": null
            },
            "challenge": "aIfQuw1Yo4AgEFpeu7Mx/w==",
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -257
                },
                {
                    "type": "public-key",
                    "alg": -37
                },
                {
                    "type": "public-key",
                    "alg": -35
                },
                {
                    "type": "public-key",
                    "alg": -258
                },
                {
                    "type": "public-key",
                    "alg": -38
                },
                {
                    "type": "public-key",
                    "alg": -36
                },
                {
                    "type": "public-key",
                    "alg": -259
                },
                {
                    "type": "public-key",
                    "alg": -39
                },
                {
                    "type": "public-key",
                    "alg": -8
                }
            ],
            "timeout": 300000,
            "attestation": "direct",
            "authenticatorSelection": {
                "requireResidentKey": true,
                "userVerification": "required"
            },
            "excludeCredentials": [],
            "extensions": {
                "exts": true,
                "uvm": true
            },
            "status": "ok",
            "errorMessage": ""
        }
        "#
        .trim();
        let res = IherbSanitizer.sanitize(input);

        let parsed: Value = serde_json::from_str(&res).unwrap();
        let retrieved = parsed
            .as_object()
            .expect("Should be a JSON object")
            .get("user")
            .expect("Should have a user object")
            .as_object()
            .expect("Should be a JSON object")
            .get("displayName")
            .expect("Should have a displayName entry")
            .as_str()
            .expect("Should be a string");
        assert_eq!("justatest@user.com", retrieved);
    }
}
