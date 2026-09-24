package com.cybershieldai.ui.scan

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.cybershieldai.ui.components.SectionCard
import com.cybershieldai.utils.OfflineResult
import com.cybershieldai.viewmodel.ScanViewModel
import com.cybershieldai.ui.theme.TextSecondary
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors

/**
 * Camera + Google ML Kit barcode/QR scanning. Decodes locally; decoded content
 * is then sent to backend URL/QR analysis. Camera permission requested in-context.
 */
@Composable
fun QrScannerScreen() {
    val context = LocalContext.current
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA)
                    == PackageManager.PERMISSION_GRANTED
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> hasPermission = granted }

    if (!hasPermission) {
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text("Camera access is needed to scan QR codes.",
                style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text("The camera is used only while the scanner is open. " +
                 "QR contents are analyzed locally first.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                modifier = Modifier.padding(bottom = 16.dp))
            Button(onClick = { permissionLauncher.launch(Manifest.permission.CAMERA) }) {
                Text("Grant Camera Permission")
            }
        }
        return
    }

    var scanned by remember { mutableStateOf<String?>(null) }
    var detailsAllowed by remember { mutableStateOf(false) }
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
    val lifecycleOwner = LocalLifecycleOwner.current
    val mainExecutor = remember { ContextCompat.getMainExecutor(context) }

    // Local pre-check BEFORE anything is displayed or analyzed further.
    val precheck = remember(scanned) { localQrPrecheck(scanned) }
    val dangerous = precheck != null && precheck.riskScore >= 40

    // Spec §9: a suspicious QR NEVER opens automatically — gate behind the
    // danger interstitial with [Cancel] / [View Safe Details].
    if (scanned != null && dangerous && !detailsAllowed) {
        AlertDialog(
            onDismissRequest = { scanned = null },
            title = { Text("🔴 DANGEROUS QR CODE",
                color = com.cybershieldai.ui.theme.severityColor("HIGH")) },
            text = {
                Text("This QR code points to content with risk indicators " +
                    "(${precheck?.riskScore ?: 0}/100):\n\n" +
                    (precheck?.indicators ?: listOf("No details")).joinToString("\n") { "• $it" } +
                    "\n\nDo not open it. Never enter passwords, OTPs, or payment " +
                    "details after following a QR code.")
            },
            confirmButton = {
                TextButton(onClick = { detailsAllowed = true }) { Text("View Safe Details") }
            },
            dismissButton = {
                TextButton(onClick = {
                    scanned = null
                    detailsAllowed = false
                }) { Text("Cancel") }
            }
        )
    }

    DisposableEffect(Unit) {
        onDispose { analysisExecutor.shutdown() }
    }

    Column(Modifier.fillMaxSize().padding(16.dp),
           verticalArrangement = Arrangement.spacedBy(12.dp)) {
        AndroidView(
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val providerFuture = ProcessCameraProvider.getInstance(ctx)
                providerFuture.addListener({
                    val provider = providerFuture.get()
                    val preview = Preview.Builder().build().also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }
                    val scanner = BarcodeScanning.getClient()
                    val analysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                    analysis.setAnalyzer(analysisExecutor) { imageProxy ->
                        processFrame(imageProxy, scanner) { value ->
                            // Compose state must be written on the main thread
                            mainExecutor.execute {
                                if (scanned == null) scanned = value
                            }
                        }
                    }
                    try {
                        provider.unbindAll()
                        provider.bindToLifecycle(
                            lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA,
                            preview, analysis
                        )
                    } catch (_: Exception) {
                        // Camera busy (e.g. another app) — retry on next open
                    }
                }, mainExecutor)
                previewView
            },
            modifier = Modifier.fillMaxWidth().height(320.dp)
        )

        if (scanned == null) {
            Text("Point the camera at a QR code. Nothing is decoded until the code is clearly visible.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        } else {
            SectionCard {
                Text("Decoded content", style = MaterialTheme.typography.titleMedium)
                Text(scanned!!, style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary)
                Spacer(Modifier.height(8.dp))
                QrAnalyzeSection(content = scanned!!)
                Spacer(Modifier.height(4.dp))
                TextButton(onClick = {
                    scanned = null
                    detailsAllowed = false
                }) { Text("Scan next code") }
            }
        }
    }
}

/**
 * On-device pre-check of decoded QR content. URLs get structural URL rules,
 * everything else gets message scam rules. Runs BEFORE any backend call or
 * UI disclosure — nothing dangerous is ever rendered without a warning.
 */
private fun localQrPrecheck(content: String?): OfflineResult? {
    val c = content?.trim() ?: return null
    return if (c.startsWith("http://") || c.startsWith("https://") ||
        c.contains("www.", ignoreCase = true)) {
        com.cybershieldai.utils.OfflineAnalyzer.analyzeUrl(c)
    } else {
        com.cybershieldai.utils.OfflineAnalyzer.analyzeMessage(c)
        ?: OfflineResult(
            type = "QR", riskScore = 0, severity = "SAFE", classification = "SAFE",
            indicators = listOf("Plain text content — no local risk indicators"),
            recommendation = "Content looks plain text. Still avoid entering credentials on pages reached via QR codes."
        )
    }
}

@OptIn(ExperimentalGetImage::class)
private fun processFrame(
    imageProxy: ImageProxy,
    scanner: BarcodeScanner,
    onResult: (String) -> Unit
) {
    val mediaImage = imageProxy.image
    if (mediaImage == null) {
        imageProxy.close()
        return
    }
    val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
    scanner.process(image)
        .addOnSuccessListener { barcodes ->
            barcodes.firstOrNull()?.rawValue?.let { onResult(it) }
        }
        .addOnCompleteListener { imageProxy.close() }
}

@Composable
fun QrAnalyzeSection(content: String) {
    val vm: ScanViewModel = viewModel()
    val state by vm.state.collectAsState()
    LaunchedEffect(content) { vm.scanQr(content) }
    ScanResultView(state)
}
