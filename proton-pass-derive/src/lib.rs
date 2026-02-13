use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Item};

#[proc_macro_derive(Error)]
pub fn derive_error(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let expanded = quote! {
        impl std::error::Error for #name {}
        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    };

    // Hand the output tokens back to the compiler
    TokenStream::from(expanded)
}

/// Attribute macro for FFI record/struct types
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: derives uniffi::Record
/// - wasm: derives tsify::Tsify, serde::Serialize, serde::Deserialize
///
/// # Example
/// ```
/// #[ffi_type]
/// pub struct MyStruct {
///     pub field: String,
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_type(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);

    let expanded = quote! {
        #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
        #[cfg_attr(feature = "wasm", derive(tsify::Tsify, serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
        #input
    };

    TokenStream::from(expanded)
}

/// Attribute macro for FFI enum types
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: derives uniffi::Enum
/// - wasm: derives tsify::Tsify, serde::Serialize, serde::Deserialize
///
/// # Example
/// ```
/// #[ffi_enum]
/// pub enum MyEnum {
///     Variant1,
///     Variant2(String),
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_enum(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);

    let expanded = quote! {
        #[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
        #[cfg_attr(feature = "wasm", derive(tsify::Tsify, serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
        #input
    };

    TokenStream::from(expanded)
}

/// Attribute macro for FFI error types
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: derives uniffi::Error
/// - wasm: derives tsify::Tsify, serde::Serialize, serde::Deserialize
///
/// Note: You should also derive Debug for error types
///
/// # Example
/// ```
/// #[ffi_error]
/// #[derive(Debug)]
/// pub enum MyError {
///     InvalidInput,
///     NotFound,
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_error(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);

    let expanded = quote! {
        #[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
        #[cfg_attr(feature = "uniffi", uniffi(flat_error))]
        #[cfg_attr(feature = "wasm", derive(tsify::Tsify, serde::Serialize, serde::Deserialize))]
        #input
    };

    TokenStream::from(expanded)
}

/// Attribute macro for FFI object/class types
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: derives uniffi::Object
/// - wasm: Currently not applicable for objects (stateful classes)
///
/// # Example
/// ```
/// #[ffi_object]
/// pub struct MyObject {
///     state: String,
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_object(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);

    let expanded = quote! {
        #[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
        #input
    };

    TokenStream::from(expanded)
}
