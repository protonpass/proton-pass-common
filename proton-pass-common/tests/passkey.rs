use proton_pass_common::passkey::{
    CreatePasskeyIosRequest, CreatePasskeyPrfInput, CreatePasskeyPrfValues, CreatePasskeyResponse, PasskeyResult,
    ResolveChallengeResponse, generate_passkey_for_ios,
};
use proton_pass_common::passkey::{FetchError, WebauthnClientFetcher, WebauthnDomainsResponse, WebauthnFetcher};

const EXAMPLE_JSON: &str = r#"
{"attestation":"none","authenticatorSelection":{"residentKey":"preferred","userVerification":"preferred"},"challenge":"D-5y7y_E4V8NQBJrFnnhd7NCvRGhO5sBGwzfh23y8D4a_hSMyRRuTAp0hmSm6_eimM71XoYF84VUiY8e9kqavA","excludeCredentials":[],"extensions":{"credProps":true},"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"}],"rp":{"id":"webauthn.io","name":"webauthn.io"},"user":{"displayName":"uyguyhj","id":"ZFhsbmRYbG9hZw","name":"uyguyhj"}}
"#;

fn get_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().build().unwrap()
}

fn generate_passkey(domain: &str, input: &str) -> PasskeyResult<CreatePasskeyResponse> {
    let rt = get_runtime();
    rt.block_on(async move {
        proton_pass_common::passkey::generate_passkey_for_domain(domain, input, false, WebauthnFetcher::new(None)).await
    })
}

fn authenticate_with_passkey(domain: &str, passkey: &[u8], input: &str) -> PasskeyResult<ResolveChallengeResponse> {
    let rt = get_runtime();
    let passkey_clone = passkey.to_vec();
    rt.block_on(async move {
        proton_pass_common::passkey::resolve_challenge_for_domain(
            domain,
            &passkey_clone,
            input,
            false,
            WebauthnFetcher::new(None),
        )
        .await
    })
}

#[test]
fn can_generate_passkey() {
    let res = generate_passkey("https://webauthn.io", EXAMPLE_JSON);

    assert!(res.is_ok());
    let value = res.unwrap();
    assert!(!value.passkey.is_empty());

    let credential_serialized = value.response().unwrap();
    assert!(!credential_serialized.is_empty());
}

#[test]
fn with_prf() {
    let input = r#"
    {
      "rp": {
        "name": "Filekey",
        "id": "filekey.app"
      },
      "user": {
        "id": "ZFhsbmRYbG9hZw",
        "name": "Filekey",
        "displayName": "default_user"
      },
      "pubKeyCredParams": [
        {
          "type": "public-key",
          "alg": -7
        },
        {
          "type": "public-key",
          "alg": -8
        },
        {
          "type": "public-key",
          "alg": -257
        }
      ],
      "timeout": 60000,
      "authenticatorSelection": {
        "residentKey": "required"
      },
      "extensions": {
        "prf": {}
      },
      "challenge": "Rnm5npHqYiIxZSD0cAMeXrBMQzlgiomT90D3IsnwObQ="
    }
 "#;

    let res = generate_passkey("https://filekey.app", input).expect("Should be able to generate a passkey with prf");

    let prf = res.credential.client_extension_results.prf;
    assert!(prf.is_some());
}

fn generate_ios_passkey(request: CreatePasskeyIosRequest) -> PasskeyResult<CreatePasskeyResponse> {
    let rt = get_runtime();
    rt.block_on(async move { generate_passkey_for_ios(request, WebauthnFetcher::new(None)).await })
}

fn base_ios_request() -> CreatePasskeyIosRequest {
    CreatePasskeyIosRequest {
        service_identifier: "www.passkeys.io".to_string(),
        rp_id: "Passkey PRF Example".to_string(),
        user_name: "user@example.com".to_string(),
        user_handle: vec![1, 2, 3, 4],
        client_data_hash: vec![0; 32],
        supported_algorithms: vec![-7, -257],
        prf: None,
    }
}

#[test]
fn ios_without_prf_has_no_prf_output() {
    let res = generate_ios_passkey(base_ios_request()).expect("should generate ios passkey");
    assert!(res.prf.is_none());
    assert!(res.credential.client_extension_results.prf.is_none());
}

#[test]
fn ios_with_prf_check_for_support_enables_prf() {
    let request = CreatePasskeyIosRequest {
        prf: Some(CreatePasskeyPrfInput { eval: None }),
        ..base_ios_request()
    };

    let res = generate_ios_passkey(request).expect("should generate ios passkey with prf support");

    let prf = res.prf.expect("prf output should be present");
    assert!(prf.supported);
    assert!(prf.first.is_none());
    assert!(prf.second.is_none());
}

#[test]
fn ios_with_prf_eval_returns_results() {
    let request = CreatePasskeyIosRequest {
        prf: Some(CreatePasskeyPrfInput {
            eval: Some(CreatePasskeyPrfValues {
                first: vec![7; 32],
                second: Some(vec![9; 32]),
            }),
        }),
        ..base_ios_request()
    };

    let res = generate_ios_passkey(request).expect("should generate ios passkey with prf eval");

    let prf = res.prf.expect("prf output should be present");
    assert!(prf.supported);
    assert!(prf.first.is_some());
    assert!(prf.second.is_some());
}

#[test]
fn create_passkey_with_exclude_credentials() {
    let input = r#"
{
  "user": {
    "id": "OWNiODgzZjE2ZDc1MjhiMzdmMmQ0NzE2YzQyYmZhZjA4OWQ0NmU1ODIwZjc3YWFlYzRlM2YyYmQ4YmRlNDA3MQ==",
    "name": "someuser@email.test",
    "displayName": "someuseremail.test"
  },
  "challenge": "RKLiWkAVCwjfkZjc2eROB5/rIIp6sREy",
  "timeout": 300000,
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    }
  ],
  "authenticatorSelection": {
    "userVerification": "preferred",
    "residentKey": "required"
  },
  "excludeCredentials": [
    {
      "id": "1T8fggYjSvC9HthqI4vHgA==",
      "type": "public-key",
      "transports": [
        "internal",
        "hybrid"
      ]
    }
  ],
  "attestation": "direct",
  "rp": {
    "name": "Amazon",
    "id": "amazon.com"
  }
}
    "#;
    let res = generate_passkey("amazon.com", input).expect("Should be able to generate a passkey");
    assert!(!res.passkey.is_empty());
}

#[test]
fn create_passkey_with_null_display_name() {
    let input = r#"
{
  "rp": {
    "id": "some.web.com",
    "name": "Fido2PasswordlessTest"
  },
  "user": {
    "name": "sometest@account.test",
    "id": "MTY0OTI1MGMtMGNhNS00MDhjLTk1ZGItMjc4ZTlkOWRkYjg5",
    "displayName": null
  },
  "challenge": "vtPVXKnHdW6/gnQ7ZzdEKg==",
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
  "timeout": 60000,
  "attestation": "none",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": false,
    "userVerification": "preferred"
  },
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "zV8kTlzGt48TOWsJ+EDgMcHHxYklBvtoSsvnjGDJk+A="
    }
  ],
  "extensions": {
    "exts": true,
    "uvm": true
  },
  "status": "ok",
  "errorMessage": ""
}
    "#;

    let res = generate_passkey("some.web.com", input).expect("Should be able to generate a passkey");
    assert!(!res.passkey.is_empty());
}

#[test]
fn register_without_prf_authenticate_with_prf() {
    let input = r#"
    {
      "rp": {
        "name": "Google",
        "id": "google.com"
      },
      "user": {
        "id": "ZFhsbmRYbG9hZw",
        "name": "google_user",
        "displayName": "Google User"
      },
      "pubKeyCredParams": [
        {
          "type": "public-key",
          "alg": -7
        },
        {
          "type": "public-key",
          "alg": -8
        },
        {
          "type": "public-key",
          "alg": -257
        }
      ],
      "timeout": 60000,
      "authenticatorSelection": {
        "residentKey": "required"
      },
      "challenge": "Rnm5npHqYiIxZSD0cAMeXrBMQzlgiomT90D3IsnwObQ="
    }
 "#;

    let passkey = generate_passkey("google.com", input).expect("Should be able to generate a passkey");

    let authentication_input = r#"
{ "challenge": "AIOPnthlZndH+wKvyBlmu0PVkXa/nwDMXS22Q7pWp+FIiEtytGZv5eF4KLiHX2dHy5H4jiM5N9MgEbyGG7X+U4MjteFMaZhaZHQL2yAH6FEFZ7mej+ThDsxsh32ZNc8sHMiAU4SG+sCp/8FHDWTX2O4x4zAt0Hl7tQCzCw==", "rpId": "google.com", "timeout": 600000, "extensions": { "prf": { "eval": { "first": "R29vZ2xlU2lnbkluUHJmSW5wdXQ=" } } } }
    "#;
    let res = authenticate_with_passkey("google.com", &passkey.passkey, authentication_input)
        .expect("Should be able to authenticate");
    assert!(!res.response.response.signature.is_empty());
    assert!(res.response.client_extension_results.prf.is_none());
}

#[tokio::test]
async fn with_related_origin_fetcher() {
    use std::sync::Arc;

    struct RelatedOriginFetcher;

    #[async_trait::async_trait(?Send)]
    impl WebauthnClientFetcher for RelatedOriginFetcher {
        async fn fetch(&self, _url: String) -> Result<WebauthnDomainsResponse, FetchError> {
            Ok(WebauthnDomainsResponse {
                origins: vec![
                    "https://aliexpress.com".to_string(),
                    "https://m.aliexpress.com".to_string(),
                ],
                final_url: None,
            })
        }
    }

    let request = r#"{
        "challenge": "dGVzdGNoYWxsZW5nZQ==",
        "rp": {"id": "m.aliexpress.com", "name": "AliExpress"},
        "user": {
            "id": "dXNlcklk",
            "name": "user@example.com",
            "displayName": "Test User"
        },
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "timeout": 60000
    }"#;

    let fetcher = WebauthnFetcher::new(Some(Arc::new(RelatedOriginFetcher)));
    let result =
        proton_pass_common::passkey::generate_passkey_for_domain("https://aliexpress.com", request, false, fetcher)
            .await;
    assert!(result.is_ok(), "Should succeed with related-origin fetcher: {result:?}");
}
