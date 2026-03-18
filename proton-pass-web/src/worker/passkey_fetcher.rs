use std::cell::RefCell;
use std::sync::Arc;

use js_sys::{Function, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use proton_pass_common::passkey::{FetchError, WebauthnClientFetcher, WebauthnDomainsResponse, WebauthnFetcher};

struct JsWebauthnFetcher {
    callback: Function,
}

// SAFETY: WASM is single-threaded; these impls are required for Arc<dyn WebauthnClientFetcher>
unsafe impl Send for JsWebauthnFetcher {}
unsafe impl Sync for JsWebauthnFetcher {}

#[async_trait::async_trait(?Send)]
impl WebauthnClientFetcher for JsWebauthnFetcher {
    async fn fetch(&self, url: String) -> Result<WebauthnDomainsResponse, FetchError> {
        let promise: Promise = self
            .callback
            .call1(&JsValue::NULL, &JsValue::from_str(&url))
            .map_err(|_| FetchError::CannotFetch)?
            .dyn_into()
            .map_err(|_| FetchError::CannotFetch)?;

        let result = JsFuture::from(promise).await.map_err(|_| FetchError::NotFound)?;

        let origins_js =
            js_sys::Reflect::get(&result, &JsValue::from_str("origins")).map_err(|_| FetchError::CannotFetch)?;

        let origins_array: js_sys::Array = origins_js.dyn_into().map_err(|_| FetchError::CannotFetch)?;

        let origins: Vec<String> = origins_array.iter().filter_map(|v| v.as_string()).collect();

        let final_url = js_sys::Reflect::get(&result, &JsValue::from_str("finalUrl"))
            .ok()
            .and_then(|v| v.as_string());

        Ok(WebauthnDomainsResponse { origins, final_url })
    }
}

thread_local! {
    static WEBAUTHN_FETCHER: RefCell<Option<Arc<dyn WebauthnClientFetcher>>> = RefCell::new(None);
}

#[wasm_bindgen]
pub fn register_webauthn_fetcher(callback: Function) {
    let fetcher = Arc::new(JsWebauthnFetcher { callback }) as Arc<dyn WebauthnClientFetcher>;
    WEBAUTHN_FETCHER.with(|f| *f.borrow_mut() = Some(fetcher));
}

pub fn get_webauthn_fetcher() -> WebauthnFetcher {
    let client = WEBAUTHN_FETCHER.with(|f| f.borrow().clone());
    WebauthnFetcher::new(client)
}
