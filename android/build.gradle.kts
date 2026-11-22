import java.security.MessageDigest

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

/**
 * Copies the cross-compiled static aarch64-linux-musl Nexus binary into
 * app/src/main/jniLibs/arm64-v8a/libnexus.so and records its SHA-256 digest.
 *
 * Usage:
 *   ./gradlew syncNexusCore -PnexusCoreBinary=../target/android-arm64/nexus-cli
 */
tasks.register("syncNexusCore") {
    group = "nexus"
    description = "Sync aarch64-linux-musl Nexus binary into jniLibs/arm64-v8a/libnexus.so with SHA-256 check"

    val sourcePath = providers.gradleProperty("nexusCoreBinary")
        .orElse("../target/android-arm64/nexus-cli")
    val expectedSha256 = providers.gradleProperty("nexusCoreSha256").orNull
    val baseDir = layout.projectDirectory.asFile
    val destFile = layout.projectDirectory.file("app/src/main/jniLibs/arm64-v8a/libnexus.so").asFile
    val digestFile = layout.projectDirectory.file("app/src/main/assets/libnexus.sha256").asFile

    doLast {
        val raw = sourcePath.get()
        val candidate = java.io.File(raw)
        val src = if (candidate.isAbsolute) candidate else java.io.File(baseDir, raw)
        require(src.isFile) { "Nexus core binary not found at: ${src.absolutePath}" }

        val bytes = src.readBytes()
        require(bytes.size >= 4 && bytes[0] == 0x7f.toByte() &&
            bytes[1] == 'E'.code.toByte() && bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte()
        ) { "Refusing to package non-ELF binary: ${src.absolutePath}" }

        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }

        if (!expectedSha256.isNullOrBlank()) {
            require(sha256.equals(expectedSha256.trim(), ignoreCase = true)) {
                "SHA-256 mismatch for ${src.name}: expected $expectedSha256, got $sha256"
            }
        }

        destFile.parentFile.mkdirs()
        destFile.writeBytes(bytes)
        digestFile.parentFile.mkdirs()
        digestFile.writeText("$sha256  libnexus.so\n")
        logger.lifecycle("Synced libnexus.so (${bytes.size} bytes, sha256=$sha256)")
    }
}
