# Add project specific ProGuard rules here.

# Keep Rust FFI bindings
-keep class proton.android.pass.commonrust.** { *; }

# Keep JNA (Java Native Access) - Required for UniFFI
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-dontwarn java.awt.**
-dontwarn javax.swing.**
-dontwarn com.sun.jna.platform.**

# Keep native methods
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# Keep Jetpack Compose
-keep class androidx.compose.** { *; }
-keep class androidx.lifecycle.** { *; }

# Keep DataStore
-keep class androidx.datastore.** { *; }
