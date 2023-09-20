SHELL:=/bin/bash
MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PROJECT_ROOT := $(dir $(MAKEFILE_PATH))

MOBILE_LIB_NAME:=libproton_pass_common_mobile.so
ANDROID_JNI_DIR:=${PROJECT_ROOT}/proton-pass-mobile/android/lib/src/main/jniLibs

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
	@rm -rf proton-pass-web/pkg

.PHONY: help
help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# --- Bindings
.PHONY: kotlin-bindings
kotlin-bindings: ## Generate the kotlin bindings
	@cargo run -p proton-pass-mobile --features=uniffi/cli --bin uniffi-bindgen generate proton-pass-mobile/src/common.udl --language kotlin
	@cp proton-pass-mobile/src/proton/android/pass/commonrust/common.kt proton-pass-mobile/android/lib/src/main/java/proton/android/pass/commonrust/common.kt

.PHONY: swift-bindings
swift-bindings: ## Generate the swift bindings
	@cargo run -p proton-pass-mobile --features=uniffi/cli --bin uniffi-bindgen generate proton-pass-mobile/src/common.udl --language swift

# --- Build
.PHONY: android-dirs
android-dirs: ## Build the dir structure for android libs
	@mkdir -p ${ANDROID_JNI_DIR}/{armeabi-v7a,arm64-v8a,x86_64}

.PHONY: android-lib-armv7
android-lib-armv7: android-dirs ## Build the android library for armv7
	@cargo build -p proton-pass-mobile --release --target armv7-linux-androideabi
	@cp "target/armv7-linux-androideabi/release/${MOBILE_LIB_NAME}" "${ANDROID_JNI_DIR}/armeabi-v7a/${MOBILE_LIB_NAME}"

.PHONY: android-lib-aarch64
android-lib-aarch64: android-dirs ## Build the android library for aarch64
	@cargo build -p proton-pass-mobile --release --target aarch64-linux-android
	@cp "target/aarch64-linux-android/release/${MOBILE_LIB_NAME}" "${ANDROID_JNI_DIR}/arm64-v8a/${MOBILE_LIB_NAME}"

.PHONY: android-lib-x86_64
android-lib-x86_64: android-dirs ## Build the android library for x86_64
	@cargo build -p proton-pass-mobile --release --target x86_64-linux-android
	@cp "target/x86_64-linux-android/release/${MOBILE_LIB_NAME}" "${ANDROID_JNI_DIR}/x86_64/${MOBILE_LIB_NAME}"

.PHONY: android
android: android-lib-aarch64 android-lib-armv7 android-lib-x86_64 ## Build all the android variants
	@cd ${PROJECT_ROOT}/proton-pass-mobile/android && ./gradlew :lib:assembleRelease

.PHONY: web
web: ## Build the web artifacts
	@wasm-pack build proton-pass-web