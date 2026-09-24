package com.cybershieldai.utils

import android.content.Context
import java.util.UUID

/**
 * Anonymous, user-scoped device identifier (random UUID, no hardware IDs).
 * Used to group scan history without collecting personal data.
 */
object DeviceIdProvider {
    private const val PREFS = "cybershield_device"
    private const val KEY = "device_id"

    private var cached: String? = null

    fun init(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        cached = prefs.getString(KEY, null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString(KEY, it).apply()
        }
    }

    fun get(): String? = cached
}
