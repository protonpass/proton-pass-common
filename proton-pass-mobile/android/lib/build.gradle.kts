import java.util.Properties
import java.io.FileInputStream
import java.io.IOException


plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("signing")
    id("com.vanniktech.maven.publish") version "0.22.0"
}

val privateProperties = Properties().apply {
    try {
        load(FileInputStream("${rootProject.projectDir}/private.properties"))
    } catch (e: IOException) {
        logger.warn("private.properties file doesn't exist. Full error message: $e")
    }
}

val gitHubDomain = "GITHUB_PROTONMAIL_DOMAIN".fromVariable()
val mavenUrl = "MAVEN_URL".fromVariable()
val mavenUser = "mavenCentralUsername".fromVariable()
val mavenPassword = "mavenCentralPassword".fromVariable()
val mavenSigningKey = "MAVEN_SIGNING_KEY".fromVariable()
val mavenSigningKeyPassword = "MAVEN_SIGNING_KEY_PASSWORD".fromVariable()


android {
    namespace = "proton.android.pass.commonrust"
    compileSdk = 33

    defaultConfig {
        minSdk = 24
        targetSdk = 33

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        proguardFiles(
            getDefaultProguardFile("proguard-android-optimize.txt"),
            "proguard-rules.pro"
        )
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

mavenPublishing {
    group = "me.proton.pass.common"
    version = "0.8.3"
    pom {
        scm {
            connection.set(gitHubDomain)
            developerConnection.set(gitHubDomain)
            url.set(gitHubDomain)
        }
    }
}

signing {
    useInMemoryPgpKeys(mavenSigningKey, mavenSigningKeyPassword)
}


dependencies {
    val COROUTINES = "1.6.4"
    val JNA = "5.13.0"

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${COROUTINES}")
    implementation("net.java.dev.jna:jna:${JNA}@aar")
}

fun String.fromVariable(): String {
    val value = System.getenv(this) ?: "${privateProperties[this]}"
    if (value.isEmpty()) {
        logger.warn("Variable $this is not set!")
    }
    return value
}
