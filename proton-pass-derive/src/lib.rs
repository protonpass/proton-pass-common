use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, DeriveInput, Item, LitStr, Token,
};

/// Parsed attributes for FFI type macros
struct FfiTypeAttrs {
    mobile_name: Option<String>,
    web_name: Option<String>,
}

impl Parse for FfiTypeAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut mobile_name = None;
        let mut web_name = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value: LitStr = input.parse()?;

            match key.to_string().as_str() {
                "mobile_name" => mobile_name = Some(value.value()),
                "web_name" => web_name = Some(value.value()),
                _ => return Err(syn::Error::new(key.span(), "Unknown attribute")),
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(FfiTypeAttrs { mobile_name, web_name })
    }
}

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

/// Attribute macro for FFI types (structs and enums)
///
/// Automatically applies the appropriate derives for enabled FFI targets:
/// - uniffi: derives uniffi::Record for structs, uniffi::Enum for enums
/// - wasm: derives tsify::Tsify, serde::Serialize, serde::Deserialize
///
/// # Examples
/// ```
/// #[ffi_type]
/// pub struct MyStruct {
///     pub field: String,
/// }
///
/// #[ffi_type(mobile_name = "MobileType", web_name = "WebType")]
/// pub enum MyEnum {
///     Variant1,
///     Variant2(String),
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_type(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = if attr.is_empty() {
        FfiTypeAttrs {
            mobile_name: None,
            web_name: None,
        }
    } else {
        parse_macro_input!(attr as FfiTypeAttrs)
    };

    let input = parse_macro_input!(item as Item);

    let uniffi_derive = match &input {
        Item::Struct(_) => quote! { uniffi::Record },
        Item::Enum(_) => quote! { uniffi::Enum },
        _ => panic!("ffi_type can only be used on structs or enums"),
    };

    let mobile_rename = if let Some(name) = attrs.mobile_name {
        quote! { #[cfg_attr(feature = "uniffi", uniffi(export_name = #name))] }
    } else {
        quote! {}
    };

    let web_rename = if let Some(name) = attrs.web_name {
        quote! { #[cfg_attr(feature = "wasm", serde(rename = #name))] }
    } else {
        quote! {}
    };

    let expanded = quote! {
        #[cfg_attr(feature = "uniffi", derive(#uniffi_derive))]
        #mobile_rename
        #[cfg_attr(feature = "wasm", derive(tsify::Tsify, serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
        #web_rename
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
///
/// #[ffi_object(mobile_name = "MobileObject")]
/// pub struct MyOtherObject {
///     state: String,
/// }
/// ```
#[proc_macro_attribute]
pub fn ffi_object(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = if attr.is_empty() {
        FfiTypeAttrs {
            mobile_name: None,
            web_name: None,
        }
    } else {
        parse_macro_input!(attr as FfiTypeAttrs)
    };

    let input = parse_macro_input!(item as Item);

    let mobile_rename = if let Some(name) = attrs.mobile_name {
        quote! { #[cfg_attr(feature = "uniffi", uniffi(export_name = #name))] }
    } else {
        quote! {}
    };

    let expanded = quote! {
        #[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
        #mobile_rename
        #input
    };

    TokenStream::from(expanded)
}
