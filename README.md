# Proton Pass Common

This repository contains the source code for the common library that's used across all clients (for now, Android, iOS and web).

## Structure

This repository is structured into 3 main modules:

- `proton-pass-common`: Pure rust, contains the core code for all the functions, with tests and everything.
- `proton-pass-mobile`: Contains the necessary glue code for exporting the library to mobile clients (android and iOS) using UniFFI.
- `proton-pass-web`: Contains the necessary glue code for exporting the library to web clients (using `wasm-pack`).

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

### Generate a release

In order to generate a new release, please follow these steps:

1. Make sure the `CHANGELOG.md` document has been updated.
2. Make sure you have `cargo-release` installed (`cargo install cargo-release`).
3. Run `cargo release [major|minor|patch] --workspace`. It will do a dry-run, it won't actually change anything.
4. If the steps look alright to you, run again `cargo release [major|minor|patch] --workspace --execute`.
5. Create a tag using `git tag <VERSION_NUMBER>`.
6. Push the changes and the tag.

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

Finally, edit your `$CARGO_HOME/config.toml` or create a `.cargo/config.toml` in this project and add the following contents:

```toml
[target.armv7-linux-androideabi]
ar = "PATH_TO_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/ar"
linker = "PATH_TO_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi30-clang"

[target.aarch64-linux-android]
ar = "PATH_TO_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/ar"
linker = "PATH_TO_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"

[target.x86_64-linux-android]
ar = "PATH_TO_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/ar"
linker = "PATH_TO_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang"
```

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
There is two ways to update the package either you call:
`make ios-package` and wait for the process to finish to have an updated package
or you can do it by hand

- Calling `make clean`, cleans the project
- Calling `make swift-bindings`, generates the bindings
- Calling `make ios-xcframework`, create the xcframework and update the Package

You should then have an up-to-date package that you can drag and drop in the `LocalPackages` directory in the Pass project.

Link to the UniFFI guide: https://mozilla.github.io/uniffi-rs/

### Web

Before being able to build the web artifacts you'll need to follow these steps for setting up the required tools:

1. Install `wasm-pack`: https://rustwasm.github.io/wasm-pack/installer/
2. Add the wasm32-unknown-unknown target: `rustup target add wasm32-unknown-unknown`
3. Add wasm2js with `brew install binaryen`

Then run `make web` and if everything worked, you're good to go!

Link for the RustWasm book: https://rustwasm.github.io/docs/book/introduction.html

## License

The code and data files in this distribution are licensed under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See <https://www.gnu.org/licenses/> for a copy of this license.

See [LICENSE](LICENSE) file
