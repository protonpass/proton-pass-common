ROOT := ../..

.PHONY: debug debug-bindings

# Fast iteration: aarch64 .so only (Apple Silicon + physical devices)
debug:
	$(MAKE) -C $(ROOT) android-lib-aarch64
	./gradlew :lib:assembleDebug --no-configuration-cache

# Like debug but also regenerates UniFFI Kotlin bindings (use when Rust interface changed)
debug-bindings:
	$(MAKE) -C $(ROOT) kotlin-bindings android-lib-aarch64
	./gradlew :lib:assembleDebug --no-configuration-cache
