package com.cybershieldai.ui.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.ui.theme.TextSecondary
import com.cybershieldai.ui.theme.severityColor

/**
 * Network Security: displays only what Android legitimately exposes to a
 * third-party app — connectivity state, transport type, VPN presence, and
 * (pre-API 29) Wi-Fi security metadata. No traffic inspection, no HTTPS
 * decryption, no packet capture. Where APIs are restricted, the UI says so.
 */
@Composable
fun NetworkScreen() {
    val context = LocalContext.current
    var netInfo by remember { mutableStateOf<NetInfo?>(null) }
    var vpnActive by remember { mutableStateOf<Boolean?>(null) }

    LaunchedEffect(Unit) {
        netInfo = readNetwork(context)
        vpnActive = readVpn(context)
        try {
            com.cybershieldai.data.repository.EventRepository(context)
                .recordManual("NETWORK", "INFO", 0,
                    listOf("Network posture reviewed"), "Network check", backendUsed = false)
        } catch (_: Exception) { }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("Network Security", style = MaterialTheme.typography.headlineMedium)

        val info = netInfo
        if (info == null) {
            SectionCard { Text("Network state is unavailable on this device.",
                color = TextSecondary, style = MaterialTheme.typography.bodyLarge) }
        } else {
            SectionCard {
                Text("Current network", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                NetRow("Connection", info.transport)
                NetRow("Internet available", if (info.hasInternet) "Yes" else "No")
                NetRow("Metered connection", if (info.metered) "Yes" else "No")
                NetRow("Wi-Fi security", info.wifiSecurity)
                if (info.ssid.isNotEmpty()) NetRow("Network name", info.ssid)
            }

            SectionCard {
                Text("VPN status", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                when (vpnActive) {
                    true -> Row {
                        Text("Active VPN detected", color = severityColor("SAFE"),
                            style = MaterialTheme.typography.bodyLarge)
                    }
                    false -> Text("No VPN active", color = severityColor("MEDIUM"),
                        style = MaterialTheme.typography.bodyLarge)
                    null -> Text("Unable to determine VPN status on this Android version.",
                        color = TextSecondary, style = MaterialTheme.typography.bodyMedium)
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    "A VPN encrypts traffic between your device and the VPN provider. It does not make malicious links safe — CyberShield still checks every URL.",
                    style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
        }

        SectionCard {
            Text("What CyberShield does NOT do", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            listOf(
                "No traffic content inspection — encrypted data stays encrypted",
                "No packet capture of other apps",
                "No HTTPS interception or certificate manipulation",
                "No DNS query logging"
            ).forEach {
                Text("• $it", style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
        }
    }
}

@Composable
private fun NetRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
        Text(value, style = MaterialTheme.typography.bodyLarge, color = TextSecondary)
    }
}

private data class NetInfo(
    val transport: String,
    val hasInternet: Boolean,
    val metered: Boolean,
    val wifiSecurity: String,
    val ssid: String
)

private fun readNetwork(context: Context): NetInfo? {
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
    val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return null
    val transport = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile data"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
        else -> "Other"
    }
    var wifiSecurity = "N/A (not on Wi-Fi)"
    var ssid = ""
    if (transport == "Wi-Fi") {
        if (Build.VERSION.SDK_INT >= 29) {
            // Android 10+: apps can't read Wi-Fi security without location grant;
            // being honest about this instead of guessing.
            wifiSecurity = "Managed by system (Android 10+ restriction)"
        } else {
            @Suppress("DEPRECATION")
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            @Suppress("DEPRECATION")
            val info = wm?.connectionInfo
            wifiSecurity = if (info != null) {
                ssid = info.ssid?.removeSurrounding("\"") ?: ""
                when {
                    info.ssid == "<unknown ssid>" -> "Requires location permission"
                    else -> "Check the lock icon in quick settings"
                }
            } else "Unknown"
        }
    }
    return NetInfo(
        transport = transport,
        hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
        metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
        wifiSecurity = wifiSecurity,
        ssid = ssid
    )
}

private fun readVpn(context: Context): Boolean? {
    return try {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        cm.allNetworks.any { net ->
            val caps = cm.getNetworkCapabilities(net)
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    } catch (e: SecurityException) {
        null
    }
}
