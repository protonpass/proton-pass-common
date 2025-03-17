SHELL:=/bin/bash
MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PROJECT_ROOT := $(dir $(MAKEFILE_PATH))

# Pass
MOBILE_LIB_NAME:=libproton_pass_common_mobile.so
ANDROID_BINDINGS_DIR:=${PROJECT_ROOT}/proton-pass-mobile/android/lib/src/main/java/proton/android/pass/commonrust
ANDROID_JNI_DIR:=${PROJECT_ROOT}/proton-pass-mobile/android/lib/src/main/jniLibs
IOS_HEADER_DIR:=${PROJECT_ROOT}/proton-pass-mobile/iOS/headers
IOS_FRAMEWORK_DIR:=${PROJECT_ROOT}/proton-pass-mobile/iOS/frameworks
IOS_LIB_DIR:=${PROJECT_ROOT}/proton-pass-mobile/iOS/libs
IOS_LIB_NAME:=libproton_pass_common_mobile.a
IOS_PACKAGE_DIR:=${PROJECT_ROOT}/proton-pass-mobile/iOS/PassRustCore
IOS_XCFRAMEWORK_NAME:=RustFramework.xcframework
WEB_DIR:=${PROJECT_ROOT}/proton-pass-web
WEB_BUILD_DIR:=${WEB_DIR}/dist
WEB_TEST_DIR:=${WEB_DIR}/test
WEB_TEST_BUILD_DIR:=${WEB_DIR}/test/pkg

.PHONY: default
default: help

# --- Project management
.PHONY: fmt
fmt: ## Format the project
	@cargo fmt --all

.PHONY: lint
lint: ## Lint the project
	@cargo clippy --all --all-targets

.PHONY: test
test: ## Run the library tests
	@command_exists() { command -v cargo-nextest >/dev/null 2>&1; }; if command_exists cargo-nextest; then cargo nextest run; else cargo test; fi

.PHONY: bench
bench: ## Run the benchmarks
	@cargo bench -p proton-pass-common

.PHONY: totp-bench
totp-bench: ## Run the TOTP benchmarks
	@cargo bench -p proton-pass-totp

.PHONY: clean
clean: ## Remove compile artifacts
	@cargo clean
	@rm -rf proton-pass-mobile/src/uniffi
	@rm -rf proton-pass-mobile/src/*.swift
	@rm -rf proton-pass-mobile/src/*.h
	@rm -rf proton-pass-mobile/src/*.modulemap
	@rm -rf proton-pass-mobile/android/lib/build
	@rm -rf proton-pass-mobile/android/lib/src/main/jniLibs
	@rm -rf proton-pass-mobile/src/proton/android/pass/commonrust/proton_pass_common_mobile.kt
	@rm -rf proton-pass-mobile/iOS/frameworks
	@rm -rf proton-pass-mobile/iOS/headers
	@rm -rf proton-pass-mobile/iOS/PassRustCore/Sources/PassRustCore/PassRustCore.swift
	@rm -rf proton-pass-mobile/iOS/PassRustCore/*.xcframework
	@rm -rf ${WEB_BUILD_DIR}
	@rm -rf ${WEB_TEST_BUILD_DIR}
	@rm -rf proton-authenticator-mobile/src/uniffi
	@rm -rf proton-authenticator-mobile/src/*.swift
	@rm -rf proton-authenticator-mobile/src/*.h
	@rm -rf proton-authenticator-mobile/src/*.modulemap
	@rm -rf proton-authenticator-mobile/android/lib/build
	@rm -rf proton-authenticator-mobile/android/lib/src/main/jniLibs
	@rm -rf proton-authenticator-mobile/src/proton/android/authenticator/commonrust/proton_authenticator_common_mobile.kt
	@rm -rf proton-authenticator-mobile/iOS/frameworks
	@rm -rf proton-authenticator-mobile/iOS/headers
	@rm -rf proton-authenticator-mobile/iOS/AuthenticatorRustCore/Sources/AuthenticatorRustCore/AuthenticatorRustCore.swift
	@rm -rf proton-authenticator-mobile/iOS/AuthenticatorRustCore/*.xcframework

.PHONY: help
help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# --- Bindings
.PHONY: kotlin-bindings
kotlin-bindings: ## Generate the kotlin bindings
	@cargo run -p proton-pass-mobile --features=uniffi/cli --bin uniffi-bindgen generate proton-pass-mobile/src/common.udl --language kotlin
	@mkdir -p ${ANDROID_BINDINGS_DIR}
	@cp proton-pass-mobile/src/proton/android/pass/commonrust/proton_pass_common_mobile.kt ${ANDROID_BINDINGS_DIR}/proton_pass_common_mobile.kt

.PHONY: swift-bindings
swift-bindings: swift-dirs ## Generate the swift bindings
	@cargo run -p proton-pass-mobile --features=uniffi/cli --bin uniffi-bindgen generate proton-pass-mobile/src/common.udl --language swift
	@cp proton-pass-mobile/src/RustFrameworkFFI.h ${IOS_HEADER_DIR}/RustFrameworkFFI.h
	@cp proton-pass-mobile/src/RustFrameworkFFI.modulemap ${IOS_HEADER_DIR}/module.modulemap
	@cp proton-pass-mobile/src/RustFramework.swift ${IOS_PACKAGE_DIR}/Sources/PassRustCore/PassRustCore.swift

# --- Build
.PHONY: swift-dirs
swift-dirs: ## Build the dir structure for swift libs
	@mkdir -p ${IOS_HEADER_DIR}
	@mkdir -p ${IOS_FRAMEWORK_DIR}
	@mkdir -p ${IOS_PACKAGE_DIR}/Sources/PassRustCore

.PHONY: ios-lib-macos
ios-lib-macos: ## Build the iOS library for macOS arm
	@cargo build -p proton-pass-mobile --release --target aarch64-apple-darwin

.PHONY: ios-lib-ios
ios-lib-ios: ## Build the iOS library for iOS
	@cargo build -p proton-pass-mobile --release --target aarch64-apple-ios

.PHONY: ios-lib-ios-sim
ios-lib-ios-sim: ## Build the iOS library for iOS arm simulators
	@cargo build -p proton-pass-mobile --release --target aarch64-apple-ios-sim

.PHONY: ios-xcframework
ios-xcframework: ios-lib-macos ios-lib-ios ios-lib-ios-sim ## Build the iOS xcframework
	@xcodebuild -create-xcframework \
               -library "target/aarch64-apple-ios/release/${IOS_LIB_NAME}" \
               -headers proton-pass-mobile/iOS/headers \
               -library "target/aarch64-apple-ios-sim/release/${IOS_LIB_NAME}" \
               -headers proton-pass-mobile/iOS/headers \
               -library "target/aarch64-apple-darwin/release/${IOS_LIB_NAME}" \
               -headers proton-pass-mobile/iOS/headers \
               -output "${IOS_FRAMEWORK_DIR}/${IOS_XCFRAMEWORK_NAME}"
	@cp -R "${IOS_FRAMEWORK_DIR}/${IOS_XCFRAMEWORK_NAME}" "${IOS_PACKAGE_DIR}/${IOS_XCFRAMEWORK_NAME}"

.PHONY: ios-package
ios-package: clean swift-bindings ios-xcframework ## Update the iOS package

.PHONY: android-dirs
android-dirs: ## Build the dir structure for android libs
	@mkdir -p ${ANDROID_JNI_DIR}/{armeabi-v7a,arm64-v8a,x86_64}

.PHONY: android-lib-armv7
android-lib-armv7: android-dirs ## Build the android library for armv7
	@cargo build -p proton-pass-mobile --release --target armv7-linux-androideabi
	@arm-none-eabi-strip "target/armv7-linux-androideabi/release/${MOBILE_LIB_NAME}" || arm-linux-gnueabihf-strip "target/armv7-linux-androideabi/release/${MOBILE_LIB_NAME}" || echo "Could not strip armv7 shared library"
	@cp "target/armv7-linux-androideabi/release/${MOBILE_LIB_NAME}" "${ANDROID_JNI_DIR}/armeabi-v7a/${MOBILE_LIB_NAME}"

.PHONY: android-lib-aarch64
android-lib-aarch64: android-dirs ## Build the android library for aarch64
	@cargo build -p proton-pass-mobile --release --target aarch64-linux-android
	@aarch64-linux-gnu-strip "target/aarch64-linux-android/release/${MOBILE_LIB_NAME}" || echo "Could not strip aarch64 shared library"
	@cp "target/aarch64-linux-android/release/${MOBILE_LIB_NAME}" "${ANDROID_JNI_DIR}/arm64-v8a/${MOBILE_LIB_NAME}"

.PHONY: android-lib-x86_64
android-lib-x86_64: android-dirs ## Build the android library for x86_64
	@cargo build -p proton-pass-mobile --release --target x86_64-linux-android
	@strip "target/x86_64-linux-android/release/${MOBILE_LIB_NAME}" || echo "Could not strip x86_64 shared library"
	@cp "target/x86_64-linux-android/release/${MOBILE_LIB_NAME}" "${ANDROID_JNI_DIR}/x86_64/${MOBILE_LIB_NAME}"

.PHONY: android
android: android-lib-aarch64 android-lib-armv7 android-lib-x86_64 ## Build all the android variants
	@cd ${PROJECT_ROOT}/proton-pass-mobile/android && ./gradlew :lib:assembleRelease

# --- Web
.PHONY: web-setup
web-setup:
	@rm -rf "${WEB_BUILD_DIR}" && mkdir "${WEB_BUILD_DIR}"

.PHONY: web-worker
web-worker: ## Build the web worker artifacts
	@echo "--- Building web-worker"
	@RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build proton-pass-web --scope protontech --features web_worker
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "worker",/g' "${WEB_DIR}/pkg/package.json"
	@mv "${WEB_DIR}/pkg" "${WEB_BUILD_DIR}/worker"

.PHONY: web-ui
web-ui: ## Build the web ui artifacts
	@echo "--- Building web-ui"
	@RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build proton-pass-web --scope protontech --features web_ui
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "ui",/g' "${WEB_DIR}/pkg/package.json"
	@echo "--- Compiling web-ui to ASM.js"
	@echo -n "export default " > "${WEB_DIR}/pkg/proton_pass_web_bg.asm.js"
	@wasm2js --emscripten -Oz "${WEB_DIR}/pkg/proton_pass_web_bg.wasm" >> "${WEB_DIR}/pkg/proton_pass_web_bg.asm.js"
	@cp "${WEB_DIR}/asm.js" "${WEB_DIR}/pkg/proton_pass_web.asm.js"
	@mv "${WEB_DIR}/pkg" "${WEB_BUILD_DIR}/ui"

.PHONY: web-password
web-password: ## Build the web password artifacts
	@echo "--- Building web-password"
	@RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build proton-pass-web --scope protontech --features web_password
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "password",/g' "${WEB_DIR}/pkg/package.json"
	@mv "${WEB_DIR}/pkg" "${WEB_BUILD_DIR}/password"

.PHONY: web
web: web-setup web-worker web-ui web-password ## Build the web artifacts
	@cp "${WEB_DIR}/package.json" "${WEB_BUILD_DIR}/package.json"

.PHONY: web-test
web-test: web-setup ## Test the web artifacts
	@rm -rf "${WEB_TEST_BUILD_DIR}" && mkdir -p "${WEB_TEST_BUILD_DIR}"
	@echo "--- Building web-worker"
	@RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build proton-pass-web --scope protontech --target nodejs --out-dir "${WEB_TEST_BUILD_DIR}/worker" --features "web_worker"
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "worker",/g' "${WEB_TEST_BUILD_DIR}/worker/package.json"

	@echo "--- Building web-ui"
	@RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build proton-pass-web --scope protontech --target nodejs --out-dir "${WEB_TEST_BUILD_DIR}/ui" --features "web_ui"
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "ui",/g' "${WEB_TEST_BUILD_DIR}/ui/package.json"

	@echo "--- Building web-password"
	@RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build proton-pass-web --scope protontech --target nodejs --out-dir "${WEB_TEST_BUILD_DIR}/password" --features "web_password"
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "password",/g' "${WEB_TEST_BUILD_DIR}/password/package.json"

	@cp "${WEB_DIR}/package.json" "${WEB_TEST_BUILD_DIR}/package.json"
	@cd ${WEB_TEST_DIR} && bun test


# Authenticator
AUTHENTICATOR_MOBILE_LIB_NAME:=libproton_authenticator_common_mobile.so
AUTHENTICATOR_ANDROID_BINDINGS_DIR:=${PROJECT_ROOT}/proton-authenticator-mobile/android/lib/src/main/java/proton/android/authenticator/commonrust
AUTHENTICATOR_ANDROID_JNI_DIR:=${PROJECT_ROOT}/proton-authenticator-mobile/android/lib/src/main/jniLibs
AUTHENTICATOR_IOS_HEADER_DIR:=${PROJECT_ROOT}/proton-authenticator-mobile/iOS/headers
AUTHENTICATOR_IOS_FRAMEWORK_DIR:=${PROJECT_ROOT}/proton-authenticator-mobile/iOS/frameworks
AUTHENTICATOR_IOS_LIB_DIR:=${PROJECT_ROOT}/proton-authenticator-mobile/iOS/libs
AUTHENTICATOR_IOS_LIB_NAME:=libproton_authenticator_common_mobile.a
AUTHENTICATOR_IOS_PACKAGE_DIR:=${PROJECT_ROOT}/proton-authenticator-mobile/iOS/AuthenticatorRustCore
AUTHENTICATOR_IOS_XCFRAMEWORK_NAME:=RustFramework.xcframework
AUTHENTICATOR_WEB_DIR:=${PROJECT_ROOT}/proton-authenticator-web
AUTHENTICATOR_WEB_BUILD_DIR:=${AUTHENTICATOR_WEB_DIR}/dist
AUTHENTICATOR_WEB_TEST_DIR:=${AUTHENTICATOR_WEB_DIR}/test
AUTHENTICATOR_WEB_TEST_BUILD_DIR:=${AUTHENTICATOR_WEB_DIR}/test/pkg

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
LIBRARY_EXT = dylib
else ifeq ($(UNAME_S), Linux)
LIBRARY_EXT = so
endif


.PHONY: authenticator-kotlin-bindings
authenticator-kotlin-bindings: ## Generate the kotlin bindings
	@cargo run -p proton-authenticator-mobile --features=uniffi/cli --bin uniffi-bindgen generate proton-authenticator-mobile/src/common.udl --language kotlin
	@mkdir -p ${AUTHENTICATOR_ANDROID_BINDINGS_DIR}
	@cp proton-authenticator-mobile/src/proton/android/authenticator/commonrust/proton_authenticator_common_mobile.kt ${AUTHENTICATOR_ANDROID_BINDINGS_DIR}/proton_authenticator_common_mobile.kt

.PHONY: authenticator-swift-bindings
authenticator-swift-bindings: authenticator-swift-dirs ## Generate the swift bindings
	@cargo run -p proton-authenticator-mobile --features=uniffi/cli --bin uniffi-bindgen generate proton-authenticator-mobile/src/common.udl --language swift
	@cp proton-authenticator-mobile/src/RustFrameworkFFI.h ${AUTHENTICATOR_IOS_HEADER_DIR}/RustFrameworkFFI.h
	@cp proton-authenticator-mobile/src/RustFrameworkFFI.modulemap ${AUTHENTICATOR_IOS_HEADER_DIR}/module.modulemap
	@cp proton-authenticator-mobile/src/RustFramework.swift ${AUTHENTICATOR_IOS_PACKAGE_DIR}/Sources/AuthenticatorRustCore/AuthenticatorRustCore.swift


.PHONY: authenticator-swift-dirs
authenticator-swift-dirs: ## Build the dir structure for swift libs
	@mkdir -p ${AUTHENTICATOR_IOS_HEADER_DIR}
	@mkdir -p ${AUTHENTICATOR_IOS_FRAMEWORK_DIR}
	@mkdir -p ${AUTHENTICATOR_IOS_PACKAGE_DIR}/Sources/AuthenticatorRustCore


.PHONY: authenticator-ios-lib-macos
authenticator-ios-lib-macos: ## Build the iOS library for macOS arm
	@cargo build -p proton-authenticator-mobile --release --target aarch64-apple-darwin

.PHONY: authenticator-ios-lib-ios
authenticator-ios-lib-ios: ## Build the iOS library for iOS
	@cargo build -p proton-authenticator-mobile --release --target aarch64-apple-ios

.PHONY: authenticator-ios-lib-ios-sim
authenticator-ios-lib-ios-sim: ## Build the iOS library for iOS arm simulators
	@cargo build -p proton-authenticator-mobile --release --target aarch64-apple-ios-sim

.PHONY: authenticator-ios-xcframework
authenticator-ios-xcframework: authenticator-ios-lib-macos authenticator-ios-lib-ios authenticator-ios-lib-ios-sim ## Build the iOS xcframework
	@xcodebuild -create-xcframework \
               -library "target/aarch64-apple-ios/release/${AUTHENTICATOR_IOS_LIB_NAME}" \
               -headers proton-authenticator-mobile/iOS/headers \
               -library "target/aarch64-apple-ios-sim/release/${AUTHENTICATOR_IOS_LIB_NAME}" \
               -headers proton-authenticator-mobile/iOS/headers \
               -library "target/aarch64-apple-darwin/release/${AUTHENTICATOR_IOS_LIB_NAME}" \
               -headers proton-authenticator-mobile/iOS/headers \
               -output "${AUTHENTICATOR_IOS_FRAMEWORK_DIR}/${AUTHENTICATOR_IOS_XCFRAMEWORK_NAME}"
	@cp -R "${AUTHENTICATOR_IOS_FRAMEWORK_DIR}/${AUTHENTICATOR_IOS_XCFRAMEWORK_NAME}" "${AUTHENTICATOR_IOS_PACKAGE_DIR}/${AUTHENTICATOR_IOS_XCFRAMEWORK_NAME}"

.PHONY: authenticator-ios-package
authenticator-ios-package: clean authenticator-swift-bindings authenticator-ios-xcframework ## Update the iOS package


.PHONY: authenticator-android-dirs
authenticator-android-dirs: ## Build the dir structure for android libs
	@mkdir -p ${AUTHENTICATOR_ANDROID_JNI_DIR}/{armeabi-v7a,arm64-v8a,x86_64}

.PHONY: authenticator-android-lib-armv7
authenticator-android-lib-armv7: authenticator-android-dirs ## Build the android library for armv7
	@cargo build -p proton-authenticator-mobile --release --target armv7-linux-androideabi
	@arm-none-eabi-strip "target/armv7-linux-androideabi/release/${AUTHENTICATOR_MOBILE_LIB_NAME}" || arm-linux-gnueabihf-strip "target/armv7-linux-androideabi/release/${AUTHENTICATOR_MOBILE_LIB_NAME}" || echo "Could not strip armv7 shared library"
	@cp "target/armv7-linux-androideabi/release/${AUTHENTICATOR_MOBILE_LIB_NAME}" "${AUTHENTICATOR_ANDROID_JNI_DIR}/armeabi-v7a/${AUTHENTICATOR_MOBILE_LIB_NAME}"

.PHONY: authenticator-android-lib-aarch64
authenticator-android-lib-aarch64: authenticator-android-dirs ## Build the android library for aarch64
	@cargo build -p proton-authenticator-mobile --release --target aarch64-linux-android
	@aarch64-linux-gnu-strip "target/aarch64-linux-android/release/${AUTHENTICATOR_MOBILE_LIB_NAME}" || echo "Could not strip aarch64 shared library"
	@cp "target/aarch64-linux-android/release/${AUTHENTICATOR_MOBILE_LIB_NAME}" "${AUTHENTICATOR_ANDROID_JNI_DIR}/arm64-v8a/${AUTHENTICATOR_MOBILE_LIB_NAME}"

.PHONY: authenticator-android-lib-x86_64
authenticator-android-lib-x86_64: authenticator-android-dirs ## Build the android library for x86_64
	@cargo build -p proton-authenticator-mobile --release --target x86_64-linux-android
	@strip "target/x86_64-linux-android/release/${AUTHENTICATOR_MOBILE_LIB_NAME}" || echo "Could not strip x86_64 shared library"
	@cp "target/x86_64-linux-android/release/${AUTHENTICATOR_MOBILE_LIB_NAME}" "${AUTHENTICATOR_ANDROID_JNI_DIR}/x86_64/${AUTHENTICATOR_MOBILE_LIB_NAME}"

.PHONY: authenticator-android
authenticator-android: authenticator-android-lib-aarch64 authenticator-android-lib-armv7 authenticator-android-lib-x86_64 ## Build all the android variants
	@cd ${PROJECT_ROOT}/proton-authenticator-mobile/android && ./gradlew :lib:assembleRelease

.PHONY: authenticator-web-setup
authenticator-web-setup:
	@rm -rf "${AUTHENTICATOR_WEB_BUILD_DIR}" && mkdir "${AUTHENTICATOR_WEB_BUILD_DIR}"

.PHONY: authenticator-web-worker
authenticator-web-worker: ## Build the authenticator web worker artifacts
	@echo "--- Building authenticator-web-worker"
	@RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build proton-authenticator-web --scope protontech
	@sed -i'' -e 's/"name": "@protontech\/proton-authenticator-web",/"name": "worker",/g' "${AUTHENTICATOR_WEB_DIR}/pkg/package.json"
	@mv "${AUTHENTICATOR_WEB_DIR}/pkg" "${AUTHENTICATOR_WEB_BUILD_DIR}/worker"

.PHONY: authenticator-web
authenticator-web: authenticator-web-setup authenticator-web-worker ## Build the authenticator web artifacts
	@cp "${AUTHENTICATOR_WEB_DIR}/package.json" "${AUTHENTICATOR_WEB_BUILD_DIR}/package.json"

.PHONY: authenticator-web-test
authenticator-web-test: authenticator-web-setup ## Test the web artifacts
	@rm -rf "${AUTHENTICATOR_WEB_TEST_BUILD_DIR}" && mkdir -p "${AUTHENTICATOR_WEB_TEST_BUILD_DIR}"
	@echo "--- Building web-worker"
	@RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build proton-authenticator-web --scope protontech --target nodejs --out-dir "${AUTHENTICATOR_WEB_TEST_BUILD_DIR}/worker"
	@sed -i'' -e 's/"name": "@protontech\/proton-authenticator-web",/"name": "worker",/g' "${AUTHENTICATOR_WEB_TEST_BUILD_DIR}/worker/package.json"

	@cp "${AUTHENTICATOR_WEB_DIR}/package.json" "${AUTHENTICATOR_WEB_TEST_BUILD_DIR}/package.json"
	@cd ${AUTHENTICATOR_WEB_TEST_DIR} && bun test

.PHONY: authenticator-mobile-unit-test
authenticator-mobile-unit-test:  ## Run the unit tests for the authenticator mobile library
	@sed -e 's:uniffi = { version = "0.29.0":uniffi = { version = "0.28.3":g' proton-authenticator-mobile/Cargo.toml > proton-authenticator-mobile/Cargo.toml.uniffi
	@mv proton-authenticator-mobile/Cargo.toml.uniffi proton-authenticator-mobile/Cargo.toml
	@cargo build --release -p proton-authenticator-mobile
	@rm -rf ${PROJECT_ROOT}/proton-authenticator-mobile/android/libUnitTest/src/main/jniLibs
	@mkdir -p ${PROJECT_ROOT}/proton-authenticator-mobile/android/libUnitTest/src/main/jniLibs
	@cp "${PROJECT_ROOT}/target/release/libproton_authenticator_common_mobile.${LIBRARY_EXT}" "${PROJECT_ROOT}/proton-authenticator-mobile/android/libUnitTest/src/main/jniLibs/libuniffi_proton_authenticator_common_mobile.${LIBRARY_EXT}"

	# Generate gobley bindings
	@rm -rf ${PROJECT_ROOT}/bindings/
	@gobley-uniffi-bindgen --lib-file ${PROJECT_ROOT}/target/release/libproton_authenticator_common_mobile.a --config ${PROJECT_ROOT}/proton-authenticator-mobile/uniffi.toml -o bindings ${PROJECT_ROOT}/proton-authenticator-mobile/src/common.udl
	@cp -R ${PROJECT_ROOT}/bindings/main proton-authenticator-mobile/android/libUnitTest/src
	@rm -rf ${PROJECT_ROOT}/bindings/

	# Run unit test
	@cd ${PROJECT_ROOT}/proton-authenticator-mobile/android && ./gradlew :libUnitTest:test
