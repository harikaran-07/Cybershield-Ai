package com.cybershieldai.utils

import com.cybershieldai.data.local.CheckSnapshotDao
import com.cybershieldai.data.local.CheckSnapshotEntity
import com.cybershieldai.data.local.DatabaseProvider
import org.json.JSONArray

/**
 * "What Changed?" (spec §7) + "Last Security Check" — honest diff store.
 *
 * Every completed check (manual scan or automatic 12h check) snapshots the
 * device state: user-app packages, threat counts, privacy changes, network
 * events and the score. Changes shown in the UI are computed by diffing the
 * snapshot against the previous one — nothing is invented.
 */
object WhatChangedStore {

    /** One tappable change line, e.g. "+2 new apps" with a target screen. */
    data class Change(val text: String, val route: String)
    data class Diff(val changes: List<Change>, val criticalThreats: Int)
    data class LastCheck(
        val completedAt: Long?,
        val trigger: String?,
        val appsChecked: Int?,
        val threatsFound: Int?,
        val privacyChanges: Int?,
        val networkEvents: Int?,
        val score: Int?
    )

    private fun dao(context: android.content.Context): CheckSnapshotDao =
        DatabaseProvider.get(context).checkSnapshotDao()

    /**
     * Snapshot the current device state at the END of a check. `userPackages`
     * should be the visible user-app package list; threat/privacy/network
     * counts are the check's real tallies.
     */
    suspend fun record(
        context: android.content.Context,
        trigger: String,
        appsChecked: Int,
        threatsFound: Int,
        privacyChanges: Int,
        networkEvents: Int,
        score: Int?,
        userPackages: List<String>
    ) {
        val entity = CheckSnapshotEntity(
            completedAt = System.currentTimeMillis(),
            trigger = trigger,
            appsChecked = appsChecked,
            threatsFound = threatsFound,
            privacyChanges = privacyChanges,
            networkEvents = networkEvents,
            score = score,
            packagesJson = JSONArray(userPackages).toString(),
            changesJson = "[]" // filled by computeDiff against the prior snapshot
        )
        val dao = dao(context)
        val previous = dao.latest()
        val diff = previous?.let { computeChanges(it, entity) } ?: Diff(emptyList(), threatsFound)
        dao.insert(entity.copy(changesJson = JSONArray(diff.changes.map { it.text }).toString()))
    }

    /**
     * Diff one snapshot against the next-older one. All four spec change
     * categories: new/removed apps, permission changes, risky URLs, criticals.
     */
    fun computeChanges(previous: CheckSnapshotEntity, current: CheckSnapshotEntity): Diff {
        val changes = mutableListOf<Change>()
        val prevPkgs = jsonList(previous.packagesJson).toSet()
        val curPkgs = jsonList(current.packagesJson).toSet()
        val added = curPkgs - prevPkgs
        val removed = prevPkgs - curPkgs

        if (added.isNotEmpty()) changes += Change("+${added.size} new app${s(added.size)}", "apps")
        if (removed.isNotEmpty()) changes += Change("−${removed.size} app${s(removed.size)} removed", "apps")
        if (current.privacyChanges > previous.privacyChanges) {
            val d = current.privacyChanges - previous.privacyChanges
            changes += Change("+${d} permission change${s(d)}", "privacy")
        }
        if (current.networkEvents > previous.networkEvents) {
            val d = current.networkEvents - previous.networkEvents
            changes += Change("+${d} URL${s(d)} analyzed", "scan")
        }
        changes += Change(
            "${current.threatsFound} critical threat${s(current.threatsFound)}",
            "alerts"
        )
        return Diff(changes, current.threatsFound)
    }

    /** The stored "What Changed" lines of the latest check (computed at record time). */
    suspend fun latestChanges(context: android.content.Context): List<String> {
        val snapshot = dao(context).latest() ?: return emptyList()
        return jsonList(snapshot.changesJson)
    }

    suspend fun latestSnapshot(context: android.content.Context): CheckSnapshotEntity? =
        dao(context).latest()

    suspend fun lastCheck(context: android.content.Context): LastCheck {
        val s = dao(context).latest()
        return LastCheck(
            completedAt = s?.completedAt,
            trigger = s?.trigger,
            appsChecked = s?.appsChecked,
            threatsFound = s?.threatsFound,
            privacyChanges = s?.privacyChanges,
            networkEvents = s?.networkEvents,
            score = s?.score
        )
    }

    /** First-run detection: no snapshot exists yet → show "—", never zeros. */
    suspend fun hasAnyCheck(context: android.content.Context): Boolean =
        dao(context).count() > 0

    private fun jsonList(json: String): List<String> {
        val out = mutableListOf<String>()
        try {
            val arr = JSONArray(json)
            for (i in 0 until arr.length()) out.add(arr.optString(i))
        } catch (_: Exception) { }
        return out
    }

    private fun s(n: Int) = if (n == 1) "" else "s"
}
