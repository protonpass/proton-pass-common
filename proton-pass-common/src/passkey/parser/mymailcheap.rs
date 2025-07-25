use super::PasskeySanitizer;
use serde_json::Value;

/// MyMailCheap has the following special cases:
/// 1. Can send a null displayName in the user object. We will copy the name if present.
/// 2. Can send a null name in the rp object. We will set the well-known one.
pub struct MyMailCheapSanitizer;

impl PasskeySanitizer for MyMailCheapSanitizer {
    fn should_sanitize(&self, url: Option<&str>, request: &str) -> bool {
        let url_matches = url.is_some_and(|u| u.contains("mymailcheap.com") || u.contains("mailcheap.co"));
        url_matches || request.contains("mymailcheap.com") || request.contains("mailcheap.co")
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

        let user_display_name_edited = crate::passkey::utils::set_user_display_name_if_empty(&mut obj);

        let rp_name_edited = match obj.get_mut("rp") {
            Some(Value::Object(ref mut rp_obj)) => match rp_obj.get_mut("name") {
                None | Some(Value::Null) => {
                    // null rp.name. Setting a defined one
                    rp_obj.insert("name".to_string(), Value::String("mailcheap.co".to_string()));
                    true
                }
                // All is fine
                _ => false,
            },
            _ => false,
        };

        if rp_name_edited || user_display_name_edited {
            serde_json::to_string(&obj).unwrap_or(request.to_string())
        } else {
            request.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_request() {
        let input = r#"
        {
            "rp": {},
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
            "extensions": {}
        }
        "#
        .trim();
        let res = MyMailCheapSanitizer.sanitize(input);

        let parsed: Value = serde_json::from_str(&res).unwrap();
        let as_obj = parsed.as_object().expect("Should be a JSON object");

        let display_name = as_obj
            .get("user")
            .expect("Should have a user object")
            .as_object()
            .expect("Should be a JSON object")
            .get("displayName")
            .expect("Should have a displayName entry")
            .as_str()
            .expect("Should be a string");
        assert_eq!("justatest@user.com", display_name);

        let rp_name = as_obj
            .get("rp")
            .expect("Should have a rp object")
            .as_object()
            .expect("Should be a JSON object")
            .get("name")
            .expect("Should have a name entry")
            .as_str()
            .expect("Should be a string");
        assert_eq!("mailcheap.co", rp_name);
    }
}
