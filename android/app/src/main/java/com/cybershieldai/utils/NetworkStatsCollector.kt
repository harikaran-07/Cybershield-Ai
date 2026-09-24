package com.cybershieldai.utils

import com.cybershieldai.data.model.NetworkStat

/**
 * Network metadata collection — OPT-IN ONLY.
 *
 * The full module uses Android VPNService with explicit user consent
 * (see docs/architecture.md). Without the VPN session active, returns null
 * so the UI can honestly state the module is unavailable rather than fake data.
 */
object NetworkStatsCollector {

    /** Returns per-destination metadata or null if the VPN module is disabled. */
    fun snapshot(): List<NetworkStat>? {
        // VPN-based collection is consent-gated and not active by default.
        // When enabled, this returns aggregated per-destination counts only.
        return null
    }
}
