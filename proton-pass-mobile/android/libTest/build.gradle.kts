plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlinx.atomicfu")
    id("org.jetbrains.kotlin.plugin.serialization")
}

kotlin {
    jvmToolchain(17)
}

sourceSets {
    main {
        // Make sure jniLibs is treated as resources, so it is on the classpath
        resources {
            srcDir("src/main/jniLibs")
        }
    }
}

tasks.test {
    systemProperty("jna.library.path", file("src/main/jniLibs").absolutePath)

    testLogging {
        events("PASSED", "SKIPPED", "FAILED") // which events to display
        showStandardStreams = true            // show standard out/err for each test
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

dependencies {
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.jna)
    implementation(libs.okio)

    testImplementation(libs.coroutines.test)
    testImplementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.kotlinx.datetime)
    testImplementation(libs.kotlinTest)
    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.turbine)
}
