package org.nexus.android.data

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.model.AndroidKdlBuilder
import org.nexus.android.bridge.model.Ipv6Mode
import org.nexus.android.bridge.model.MeteredMode
import org.nexus.android.bridge.model.PerAppMode
import org.nexus.android.bridge.model.VpnProfileConfig
import java.io.File

data class StoredProfile(
    val id: String,
    val name: String,
    val config: VpnProfileConfig,
)

/**
 * Lightweight app-private KDL profile store backed by noBackupFilesDir/profiles/.
 * All disk & SharedPreferences operations run on Dispatchers.IO with atomic tmp-file rename
 * to prevent main-thread ANRs and partial writes on crash.
 */
class ProfileRepository(context: Context) {
    private val appContext = context.applicationContext
    private val prefs by lazy {
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }
    private val profileDir: File
        get() = File(appContext.noBackupFilesDir, "profiles").apply { if (!exists()) mkdirs() }

    suspend fun loadActiveProfile(): StoredProfile = withContext(Dispatchers.IO) {
        val id = prefs.getString(KEY_ACTIVE_ID, DEFAULT_ID) ?: DEFAULT_ID
        val kdlFile = File(profileDir, "$id.kdl")
        val kdlText = if (kdlFile.isFile) {
            kdlFile.readText(Charsets.UTF_8)
        } else {
            AndroidKdlBuilder.defaultSampleUserKdl().also { writeFileAtomic(kdlFile, it) }
        }
        val ipv6 = runCatching {
            Ipv6Mode.valueOf(prefs.getString(KEY_IPV6_MODE, Ipv6Mode.DUAL_STACK.name)!!)
        }.getOrDefault(Ipv6Mode.DUAL_STACK)
        val perApp = runCatching {
            PerAppMode.valueOf(prefs.getString(KEY_PER_APP_MODE, PerAppMode.DISALLOW_LIST.name)!!)
        }.getOrDefault(PerAppMode.DISALLOW_LIST)
        val metered = runCatching {
            MeteredMode.valueOf(prefs.getString(KEY_METERED_MODE, MeteredMode.FOLLOW_UNDERLYING.name)!!)
        }.getOrDefault(MeteredMode.FOLLOW_UNDERLYING)
        val packages = prefs.getStringSet(KEY_PACKAGES, emptySet()).orEmpty().toSet()

        StoredProfile(
            id = id,
            name = prefs.getString(KEY_ACTIVE_NAME, "默认配置") ?: "默认配置",
            config = VpnProfileConfig(
                routeExcludePrivate = prefs.getBoolean(KEY_EXCLUDE_PRIVATE, true),
                ipv6Mode = ipv6,
                perAppMode = perApp,
                packages = packages,
                meteredMode = metered,
                mtu = prefs.getInt(KEY_MTU, 9000).coerceIn(1280, 9000),
                userKdlConfig = kdlText,
            ),
        )
    }

    suspend fun saveKdl(id: String, name: String, kdlText: String) = withContext(Dispatchers.IO) {
        val safeId = id.filter { it.isLetterOrDigit() || it == '-' || it == '_' }.ifEmpty { DEFAULT_ID }
        writeFileAtomic(File(profileDir, "$safeId.kdl"), kdlText)
        prefs.edit()
            .putString(KEY_ACTIVE_ID, safeId)
            .putString(KEY_ACTIVE_NAME, name.ifBlank { safeId })
            .apply()
    }

    suspend fun saveSplitTunneling(mode: PerAppMode, packages: Set<String>) = withContext(Dispatchers.IO) {
        prefs.edit()
            .putString(KEY_PER_APP_MODE, mode.name)
            .putStringSet(KEY_PACKAGES, packages.toSet())
            .apply()
    }

    private fun writeFileAtomic(target: File, content: String) {
        val tmp = File(target.parentFile, "${target.name}.tmp")
        tmp.writeText(content, Charsets.UTF_8)
        if (!tmp.renameTo(target)) {
            target.writeText(content, Charsets.UTF_8)
            tmp.delete()
        }
    }

    companion object {
        private const val PREFS_NAME = "nexus_profiles"
        private const val DEFAULT_ID = "default"
        private const val KEY_ACTIVE_ID = "active_id"
        private const val KEY_ACTIVE_NAME = "active_name"
        private const val KEY_IPV6_MODE = "ipv6_mode"
        private const val KEY_PER_APP_MODE = "per_app_mode"
        private const val KEY_METERED_MODE = "metered_mode"
        private const val KEY_PACKAGES = "per_app_packages"
        private const val KEY_EXCLUDE_PRIVATE = "exclude_private"
        private const val KEY_MTU = "mtu"
    }
}
