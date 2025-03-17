// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.gradlePlugin.application) apply false
    alias(libs.plugins.gradlePlugin.library) apply false
    alias(libs.plugins.gradlePlugin.maven.publish) apply false
    alias(libs.plugins.gradlePlugin.kotlin.android) apply false
    alias(libs.plugins.gradlePlugin.kotlin.serialization) apply false

    id("org.jetbrains.kotlinx.atomicfu") version "0.27.0" apply false
}
