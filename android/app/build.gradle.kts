import java.io.File
import java.security.MessageDigest
import org.gradle.api.logging.Logging
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "org.nexus.android"
    compileSdk {
        version = release(37) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "org.nexus.android"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-alpha"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    packaging {
        jniLibs {
            // Mandatory for Android 10+ W^X sidecar execution from applicationInfo.nativeLibraryDir.
            useLegacyPackaging = true
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":core-bridge"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.kotlinx.coroutines.android)
    debugImplementation(libs.androidx.compose.ui.tooling)
    testImplementation(libs.junit)
}

tasks.register("syncNexusCore") {
    group = "build"
    description = "Validates AArch64 ELF header and syncs nexus sidecar binary into jniLibs + SHA-256 asset."
    val coreBinProvider = providers.gradleProperty("nexusCoreBin")
        .orElse(providers.environmentVariable("NEXUS_CORE_BIN"))
    val baseDir = layout.projectDirectory.asFile
    val outLib = layout.projectDirectory.file("src/main/jniLibs/arm64-v8a/libnexus.so").asFile
    val shaFile = layout.projectDirectory.file("src/main/assets/nexus-core.sha256").asFile
    doLast {
        val rawPath = coreBinProvider.orNull ?: return@doLast
        val candidate = File(rawPath)
        val src = if (candidate.isAbsolute) candidate else File(baseDir, rawPath)
        require(src.isFile) { "NEXUS_CORE_BIN not found: ${src.absolutePath}" }
        val bytes = src.readBytes()
        require(bytes.size >= 20) { "ELF binary too small: ${bytes.size}" }
        // Verify ELF magic \x7FELF, EI_CLASS=2 (64-bit), EI_DATA=1 (little-endian), e_machine=183 (EM_AARCH64)
        require(
            bytes[0] == 0x7F.toByte() &&
                bytes[1] == 'E'.code.toByte() &&
                bytes[2] == 'L'.code.toByte() &&
                bytes[3] == 'F'.code.toByte() &&
                bytes[4] == 2.toByte() &&
                bytes[5] == 1.toByte()
        ) { "Invalid 64-bit little-endian ELF header in ${src.name}" }
        val machine = (bytes[18].toInt() and 0xFF) or ((bytes[19].toInt() and 0xFF) shl 8)
        require(machine == 183) { "Expected e_machine=183 (AArch64), got $machine" }

        outLib.parentFile.mkdirs()
        src.copyTo(outLib, overwrite = true)

        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        shaFile.parentFile.mkdirs()
        shaFile.writeText("$digest  libnexus.so\n")
        Logging.getLogger("syncNexusCore").lifecycle("Synced nexus arm64-v8a core (${bytes.size} bytes, sha256=$digest)")
    }
}

tasks.named("preBuild") {
    dependsOn("syncNexusCore")
}
