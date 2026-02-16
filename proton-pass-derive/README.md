# proton-pass-derive

Procedural macros for FFI bindings generation across multiple platforms.

## FFI Attribute Macros

These macros automatically apply the appropriate derives for enabled FFI targets, eliminating the need for repetitive `cfg_attr` annotations.

### `#[ffi_type]` - For Structs and Enums

Use on data structures and enums that need to cross FFI boundaries. The macro automatically applies the correct derives based on whether it's a struct or enum.

**Struct Example - Before:**
```rust
#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify, serde::Serialize, serde::Deserialize))]
pub struct MyStruct {
    pub field: String,
}
```

**Struct Example - After:**
```rust
use proton_pass_derive::ffi_type;

#[ffi_type]
#[derive(Clone, Debug)]
pub struct MyStruct {
    pub field: String,
}
```

**Enum Example - Before:**
```rust
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify, serde::Serialize, serde::Deserialize))]
pub enum MyEnum {
    Variant1,
    Variant2,
}
```

**Enum Example - After:**
```rust
use proton_pass_derive::ffi_type;

#[ffi_type]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MyEnum {
    Variant1,
    Variant2,
}
```

### `#[ffi_error]` - For Error Types

Use on error enums that need to cross FFI boundaries. Automatically applies `uniffi(flat_error)`.

**Before:**
```rust
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify, serde::Serialize, serde::Deserialize))]
pub enum MyError {
    InvalidInput,
    NotFound,
}
```

**After:**
```rust
use proton_pass_derive::ffi_error;

#[ffi_error]
#[derive(Debug)]
pub enum MyError {
    InvalidInput,
    NotFound,
}
```

### `#[ffi_object]` - For Objects/Classes

Use on types that represent stateful objects in uniffi (not typically used with wasm).

**Before:**
```rust
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct MyObject {
    state: String,
}
```

**After:**
```rust
use proton_pass_derive::ffi_object;

#[ffi_object]
#[derive(Debug)]
pub struct MyObject {
    state: String,
}
```

## Supported Features

### Current Targets

- **uniffi**: Mobile FFI bindings (Kotlin/Swift) via UniFFI
- **wasm**: Web FFI bindings (TypeScript) via wasm-bindgen + tsify

### Adding New Targets

To add support for a new FFI target, edit the macro implementations in `src/lib.rs` to add the appropriate conditional derives.

## Benefits

1. **Less boilerplate**: One line instead of multiple `cfg_attr` lines
2. **Centralized**: FFI configuration in one place
3. **Consistent**: Ensures all types use the same FFI setup
4. **Maintainable**: Easy to add new targets or change configurations
5. **Type-safe**: Clear intent about what each type represents

## Legacy Macro

### `#[derive(Error)]`

Still available for backward compatibility. Implements `std::error::Error` and `std::fmt::Display` for error types.

```rust
use proton_pass_derive::Error;

#[derive(Debug, Error)]
pub enum MyError {
    SomeError,
}
```
