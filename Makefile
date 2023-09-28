SHELL:=/bin/bash
MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PROJECT_ROOT := $(dir $(MAKEFILE_PATH))

MOBILE_LIB_NAME:=libproton_pass_common_mobile.so
ANDROID_BINDINGS_DIR:=${PROJECT_ROOT}/proton-pass-mobile/android/lib/src/main/java/proton/android/pass/commonrust
ANDROID_JNI_DIR:=${PROJECT_ROOT}/proton-pass-mobile/android/lib/src/main/jniLibs
IOS_HEADER_DIR:=${PROJECT_ROOT}/proton-pass-mobile/ios/headers
IOS_FRAMEWORK_DIR:=${PROJECT_ROOT}/proton-pass-mobile/ios/frameworks
IOS_LIB_DIR:=${PROJECT_ROOT}/proton-pass-mobile/ios/libs
IOS_LIB_NAME:=libproton_pass_common_mobile.dylib
IOS_PACKAGE_DIR:=${PROJECT_ROOT}/proton-pass-mobile/ios/PassRustCore
IOS_XCFRAMEWORK_NAME:=RustFramework.xcframework

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
	@rm -rf proton-pass-web/pkg
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
               -headers proton-pass-mobile/ios/headers \
               -library "target/aarch64-apple-ios-sim/release/${IOS_LIB_NAME}" \
               -headers proton-pass-mobile/ios/headers \
               -library "target/aarch64-apple-darwin/release/${IOS_LIB_NAME}" \
               -headers proton-pass-mobile/ios/headers \
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
	@arm-none-eabi-strip "target/armv7-linux-androideabi/release/${MOBILE_LIB_NAME}" || echo "Could not strip armv7 shared library"
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

.PHONY: web
web: ## Build the web artifacts
	@wasm-pack build proton-pass-web
