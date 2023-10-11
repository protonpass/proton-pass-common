pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub fn vec_to_uint8_array(source: Vec<u8>) -> js_sys::Uint8Array {
    let js_res = js_sys::Uint8Array::new_with_length(source.len() as u32);
    for (idx, value) in source.into_iter().enumerate() {
        js_res.set_index(idx as u32, value);
    }

    js_res
}
