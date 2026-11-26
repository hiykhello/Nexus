package org.nexus.android.apps

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.util.LruCache
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Bounded off-main-thread LRU cache for installed app icons (`128` entries downsampled to target px).
 * Prevents blocking main-thread PackageManager Binder IPC & full-res bitmap decode during scrolling.
 */
object AppIconCache {
    private val cache = object : LruCache<String, ImageBitmap>(128) {}

    fun peek(packageName: String, sizePx: Int): ImageBitmap? =
        cache.get("$packageName@$sizePx")

    suspend fun load(context: Context, packageName: String, sizePx: Int): ImageBitmap? {
        val key = "$packageName@$sizePx"
        cache.get(key)?.let { return it }
        return withContext(Dispatchers.IO) {
            runCatching {
                val drawable = context.applicationContext.packageManager.getApplicationIcon(packageName)
                val target = sizePx.coerceIn(32, 160)
                val bmp = Bitmap.createBitmap(target, target, Bitmap.Config.ARGB_8888)
                val canvas = Canvas(bmp)
                drawable.setBounds(0, 0, target, target)
                drawable.draw(canvas)
                bmp.asImageBitmap().also { cache.put(key, it) }
            }.getOrNull()
        }
    }
}
