import java.util.Properties
import java.io.FileInputStream
import java.io.IOException


plugins {
    alias(libs.plugins.gradlePlugin.library)
    alias(libs.plugins.gradlePlugin.kotlin.android)
    alias(libs.plugins.gradlePlugin.maven.publish)
    id("signing")
}

val privateProperties = Properties().apply {
    try {
        load(FileInputStream("${rootProject.projectDir}/private.properties"))
    } catch (e: IOException) {
        logger.warn("private.properties file doesn't exist. Full error message: $e")
    }
}

val gitHubDomain = "GITHUB_PROTONMAIL_DOMAIN".fromVariable()
val mavenUser = "mavenCentralUsername".fromVariable()
val mavenPassword = "mavenCentralPassword".fromVariable()
val mavenSigningKey = "MAVEN_SIGNING_KEY".fromVariable()
val mavenSigningKeyPassword = "MAVEN_SIGNING_KEY_PASSWORD".fromVariable()


android {
    namespace = "proton.android.authenticator.commonrust"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()

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
    group = "me.proton.authenticator.common"
    version = "0.28.1"
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


val versionCatalog = extensions.findByType<VersionCatalogsExtension>()?.named("libs")
val jna = versionCatalog?.findLibrary("jna")?.get()?.get()
val jnaAarDependency = project.dependencies.create("$jna@aar")

dependencies {
    implementation(libs.kotlinx.coroutines.core)
    implementation(jnaAarDependency)
}

fun String.fromVariable(): String {
    val value = System.getenv(this) ?: "${privateProperties[this]}"
    if (value.isEmpty()) {
        logger.warn("Variable $this is not set!")
    }
    return value
}
