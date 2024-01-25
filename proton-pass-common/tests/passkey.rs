const EXAMPLE_JSON: &str = r#"
{"attestation":"none","authenticatorSelection":{"residentKey":"preferred","userVerification":"preferred"},"challenge":"D-5y7y_E4V8NQBJrFnnhd7NCvRGhO5sBGwzfh23y8D4a_hSMyRRuTAp0hmSm6_eimM71XoYF84VUiY8e9kqavA","excludeCredentials":[],"extensions":{"credProps":true},"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"}],"rp":{"id":"webauthn.io","name":"webauthn.io"},"user":{"displayName":"uyguyhj","id":"ZFhsbmRYbG9hZw","name":"uyguyhj"}}
"#;

fn get_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().build().unwrap()
}

#[test]
fn can_generate_passkey() {
    let rt = get_runtime();
    let res = rt.block_on(async move {
        proton_pass_common::passkey::generate_passkey_for_domain("https://webauthn.io", EXAMPLE_JSON).await
    });

    assert!(res.is_ok());
    let value = res.unwrap();
    assert!(!value.passkey.is_empty());

    let credential_serialized = value.response().unwrap();
    assert!(!credential_serialized.is_empty());
}
