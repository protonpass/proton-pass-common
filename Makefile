SHELL:=/bin/bash
MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PROJECT_ROOT := $(dir $(MAKEFILE_PATH))

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
	@cargo test -p proton-pass-common

.PHONY: bench
bench: ## Run the benchmarks
	@cargo bench -p proton-pass-common

.PHONY: clean
clean: ## Remove compile artifacts
	@cargo clean
	@rm -rf proton-pass-mobile/src/uniffi
	@rm -f proton-pass-mobile/src/*.swift
	@rm -f proton-pass-mobile/src/*.h
	@rm -f proton-pass-mobile/src/*.modulemap
	@rm -rf proton-pass-mobile/android/lib/build
	@rm -rf proton-pass-mobile/android/lib/src/main/jniLibs
	@rm -rf proton-pass-mobile/src/proton/android/pass/commonrust/proton_pass_common_mobile.kt
	@rm -rf ${WEB_BUILD_DIR}
	@rm -rf ${WEB_TEST_BUILD_DIR}
	@rm -rf proton-pass-mobile/iOS/frameworks
	@rm -rf proton-pass-mobile/iOS/headers
	@rm -rf proton-pass-mobile/iOS/PassRustCore/Sources/PassRustCore/PassRustCore.swift
	@rm -rf proton-pass-mobile/iOS/PassRustCore/*.xcframework

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
	@wasm-pack build proton-pass-web --scope protontech --features web_worker
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "worker",/g' "${WEB_DIR}/pkg/package.json"
	@mv "${WEB_DIR}/pkg" "${WEB_BUILD_DIR}/worker"

.PHONY: web-ui
web-ui: ## Build the web ui artifacts
	@echo "--- Building web-ui"
	@wasm-pack build proton-pass-web --scope protontech --features web_ui
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "ui",/g' "${WEB_DIR}/pkg/package.json"
	@echo "--- Compiling web-ui to ASM.js"
	@echo -n "export default " > "${WEB_DIR}/pkg/proton_pass_web_bg.asm.js"
	@wasm2js --emscripten -Oz "${WEB_DIR}/pkg/proton_pass_web_bg.wasm" >> "${WEB_DIR}/pkg/proton_pass_web_bg.asm.js"
	@cp "${WEB_DIR}/asm.js" "${WEB_DIR}/pkg/proton_pass_web.asm.js"
	@mv "${WEB_DIR}/pkg" "${WEB_BUILD_DIR}/ui"

.PHONY: web-password
web-password: ## Build the web password artifacts
	@echo "--- Building web-password"
	@wasm-pack build proton-pass-web --scope protontech --features web_password
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "password",/g' "${WEB_DIR}/pkg/package.json"
	@mv "${WEB_DIR}/pkg" "${WEB_BUILD_DIR}/password"

.PHONY: web
web: web-setup web-worker web-ui web-password ## Build the web artifacts
	@cp "${WEB_DIR}/package.json" "${WEB_BUILD_DIR}/package.json"

.PHONY: web-test
web-test: web-setup ## Test the web artifacts
	@rm -rf "${WEB_TEST_BUILD_DIR}" && mkdir -p "${WEB_TEST_BUILD_DIR}"
	@echo "--- Building web-worker"
	@wasm-pack build proton-pass-web --scope protontech --target nodejs --out-dir "${WEB_TEST_BUILD_DIR}/worker" --features "web_worker"
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "worker",/g' "${WEB_TEST_BUILD_DIR}/worker/package.json"

	@echo "--- Building web-ui"
	@wasm-pack build proton-pass-web --scope protontech --target nodejs --out-dir "${WEB_TEST_BUILD_DIR}/ui" --features "web_ui"
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "ui",/g' "${WEB_TEST_BUILD_DIR}/ui/package.json"

	@echo "--- Building web-password"
	@wasm-pack build proton-pass-web --scope protontech --target nodejs --out-dir "${WEB_TEST_BUILD_DIR}/password" --features "web_password"
	@sed -i'' -e 's/"name": "@protontech\/proton-pass-web",/"name": "password",/g' "${WEB_TEST_BUILD_DIR}/password/package.json"

	@cp "${WEB_DIR}/package.json" "${WEB_TEST_BUILD_DIR}/package.json"
	@cd ${WEB_TEST_DIR} && bun test
