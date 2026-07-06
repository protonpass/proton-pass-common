# uniffi-bindgen-cli

A lightweight binary crate that provides the `uniffi-bindgen` CLI tool for generating UniFFI bindings.

## Why this exists

Previously, each mobile crate (`proton-pass-mobile` and `proton-authenticator-mobile`) had its own copy of the uniffi-bindgen binary. This caused:

- Duplicate compilation of the same binary in CI
- Unnecessary compilation of all dependencies of the containing crates just to generate bindings
- Potential version mismatches between different bindgen instances

This shared crate solves these issues by:

- Providing a single, centralized uniffi-bindgen binary
- Having only the minimal dependencies required (just `uniffi` with the `cli` feature)
- Ensuring all projects use the same UniFFI version via workspace dependencies

## Usage

To generate bindings, use:

```bash
# Build the binary
cargo build -p uniffi-bindgen-cli

# Or run it directly
cargo run -p uniffi-bindgen-cli -- generate --help
```

The Makefile targets (`kotlin-bindings`, `swift-bindings`, etc.) already use this binary automatically.
