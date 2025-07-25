use proton_pass_common::passkey::{CreatePasskeyResponse, PasskeyResult};

const EXAMPLE_JSON: &str = r#"
{"attestation":"none","authenticatorSelection":{"residentKey":"preferred","userVerification":"preferred"},"challenge":"D-5y7y_E4V8NQBJrFnnhd7NCvRGhO5sBGwzfh23y8D4a_hSMyRRuTAp0hmSm6_eimM71XoYF84VUiY8e9kqavA","excludeCredentials":[],"extensions":{"credProps":true},"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"}],"rp":{"id":"webauthn.io","name":"webauthn.io"},"user":{"displayName":"uyguyhj","id":"ZFhsbmRYbG9hZw","name":"uyguyhj"}}
"#;

fn get_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().build().unwrap()
}

fn generate_passkey(domain: &str, input: &str) -> PasskeyResult<CreatePasskeyResponse> {
    let rt = get_runtime();
    rt.block_on(async move { proton_pass_common::passkey::generate_passkey_for_domain(domain, input).await })
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
