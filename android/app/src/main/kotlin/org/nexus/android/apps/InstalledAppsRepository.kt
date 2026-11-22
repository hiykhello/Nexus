package org.nexus.android.apps

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class InstalledAppEntry(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean,
)

/**
 * Enumerates installed applications for non-root VpnService per-app split tunneling.
 * Runs strictly on Dispatchers.IO because PackageManager queries perform cross-process Binder IPC.
 */
class InstalledAppsRepository(context: Context) {
    private val appContext = context.applicationContext

    suspend fun listInstalledApps(includeSystem: Boolean): List<InstalledAppEntry> =
        withContext(Dispatchers.IO) {
            val pm = appContext.packageManager
            val self = appContext.packageName
            val apps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(0)
            }
            apps.asSequence()
                .filter { it.packageName != self }
                .map { info ->
                    val system = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    InstalledAppEntry(
                        packageName = info.packageName,
                        label = pm.getApplicationLabel(info).toString(),
                        isSystemApp = system,
                    )
                }
                .filter { includeSystem || !it.isSystemApp }
                .sortedWith(compareBy<InstalledAppEntry> { it.isSystemApp }.thenBy { it.label.lowercase() })
                .toList()
        }

    companion object {
        val RECOMMENDED_BYPASS_PACKAGES: Set<String> = setOf(
            "com.google.android.projection.gearhead", // Android Auto
            "com.android.imsserviceentitlement",
            "com.android.ims",
        )
    }
}
