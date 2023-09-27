# Proton Pass Common

This repository contains the source code for the common library that's used across all clients (for now, Android, iOS and web).

## Structure

This repository is structured into 3 main modules:

- `proton-pass-common`: Pure rust, contains the core code for all the functions, with tests and everything.
- `proton-pass-mobile`: Contains the necessary glue code for exporting the library to mobile clients (android and iOS) using UniFFI.
- `proton-pass-mobile`: Contains the necessary glue code for exporting the library to web clients (using `wasm-pack`).

### Adding a new function

For every function added to the library, we need to:

1. Add it to `proton-pass-common`, marking it as public.
2. Write tests for it in `proton-pass-common/tests`.
3. Add it to the `proton-pass-mobile/src/common.udl` file.
4. Add it to the `proton-pass-mobile/src/lib.rs` file, calling the `proton-pass-common` function.
5. Add it to the `proton-pass-web/src/lib.rs` file, marking it as `#[wasm_bindgen]` and calling the `proton-pass-common` function.

### Running the tests

Only the `proton-pass-common` crate contains tests, as the other ones only contain the glue code for calling the functions from other languages.

In order to run the tests you can either call `make test` or `cargo test -p proton-pass-common`.

## Project management

### Formatting

```
$ cargo fmt --all
# or
$ make fmt
```

### Linting

```
$ cargo clippy --all --all-features
# or
$ make lint
```

### Clean build artifacts

```
$ make clean 
```

This command runs `cargo clean` and also removes all the artifacts generating when building the bindings / modules.

## Setup

Here you have the initial steps to follow for being able to build the repo for each platform.

### Android

In order to build the Android modules, you'll need to add the following targets in `rustup`:

```
$ rustup target add aarch64-linux-android
$ rustup target add x86_64-linux-android
$ rustup target add armv7-linux-androideabi
```

Then, make sure to download the NDK from Android Studio. Any recent version should work (for reference, `25.1.8937393` works).

Finally, edit the path to your NDK in `.cargo/config.toml` (TO BE DONE: Try to make this bootstrapable / workdir independant).

In order to perform the build, run `make android` and hopefully everything will work.

For generating the bindings, run `make kotlin-bindings`.

Link to the UniFFI guide: https://mozilla.github.io/uniffi-rs/

### iOS
In order to build the iOS modules, you'll need to add the following targets in rustup:
```bash
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
rustup target add aarch64-apple-darwin
```
To use rust in iOS we are leveraging the power of `Swift Packages`.

The **iOS** folder in **proton-pass-mobile** contains the scaffold of our package.
The current package is called `PassRustCore` and it is the one that is used in the Pass iOS project.

For now the update of this package must be done by hand.
You first need to update the package by:
- Calling `make clean`, cleans the project
- Calling `make swift-bindings`, generates the bindings
- Calling `make ios-xcframework`, create the xcframework and update the Package

You should then have an up-to-date package that you can drag and drop in the `LocalPackages` directory in the Pass project.

Link to the UniFFI guide: https://mozilla.github.io/uniffi-rs/

### Web

Before being able to build the web artifacts you'll need to follow these steps for setting up the required tools:

1. Install `wasm-pack`: https://rustwasm.github.io/wasm-pack/installer/
2. Add the wasm32-unknown-unknown target: `rustup target add wasm32-unknown-unknown` 

Then run `make web` and if everything worked, you're good to go!

Link for the RustWasm book: https://rustwasm.github.io/docs/book/introduction.html
