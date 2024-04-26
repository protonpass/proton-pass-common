pub fn vec_to_uint8_array(source: Vec<u8>) -> js_sys::Uint8Array {
    let js_res = js_sys::Uint8Array::new_with_length(source.len() as u32);
    for (idx, value) in source.into_iter().enumerate() {
        js_res.set_index(idx as u32, value);
    }

    js_res
}
