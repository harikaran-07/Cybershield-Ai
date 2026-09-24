package com.cybershieldai.ai

import android.content.Context
import com.cybershieldai.data.local.DatabaseProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Builds the optional security context injected into the chat prompt
 * (spec §17): the user's REAL locally-stored events and scam reports.
 * Nothing is invented — only what Room contains is passed to the model.
 */
object ChatContextBuilder {

    suspend fun build(context: Context): String? = withContext(Dispatchers.IO) {
        try {
            val db = DatabaseProvider.get(context)
            val fmt = SimpleDateFormat("MMM d, HH:mm", Locale.US)

            val events = db.securityEventDao().recent(8)
            val reports = db.communityReportDao().recent(5)

            if (events.isEmpty() && reports.isEmpty()) return@withContext null

            val sb = StringBuilder()
            if (events.isNotEmpty()) {
                sb.append("Recent locally detected security events:\n")
                for (e in events) {
                    sb.append("- ${fmt.format(Date(e.timestamp))} [${e.category}] ")
                        .append(e.classification)
                        .append(", risk ${e.riskScore}/100")
                        .append(" — ").append(e.summary.take(140)).append('\n')
                }
            }
            if (reports.isNotEmpty()) {
                sb.append("\nScam reports saved by the user on this device:\n")
                for (r in reports) {
                    sb.append("- ${r.kind.uppercase()} ${r.value} (reported ")
                        .append(fmt.format(Date(r.createdAt)))
                        .append(", status ").append(r.status).append(")\n")
                }
            }
            sb.toString()
        } catch (_: Exception) {
            null
        }
    }
}
