package com.cybershieldai.ai

import android.content.Context
import android.os.StatFs
import android.util.Log
import com.cybershieldai.data.local.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * Local AI model management (spec §20): download / install-state / delete for
 * the litert-community Qwen2.5-0.5B-Instruct q8 .task package. Everything is
 * stored in app-private storage and stays on-device (spec §18 privacy).
 *
 * Install state is REAL: derived from the model file's existence; the
 * DataStore flag is just a fast-path cache for status rows.
 */
object AiModelManager {

    private const val TAG = "CyberShieldAiModel"

    /** Official Google-published .task package (546,660,344 bytes, q8). */
    const val MODEL_ID = "Qwen2.5-0.5B-Instruct (q8 · .task · 546 MB)"
    const val MODEL_URL = "https://huggingface.co/litert-community/Qwen2.5-0.5B-Instruct/resolve/main/Qwen2.5-0.5B-Instruct_multi-prefill-seq_q8_ekv1280.task"

    private const val EXPECTED_BYTES = 546_660_344L

    /** The only model packages allowed to load: the installer's name and the
     *  original HF download name (adb-pushed files). Any other .task file in
     *  the model dir (older experiment, wrong variant, partial download) can
     *  crash the native LLM runtime — quarantine it instead. */
    private const val KNOWN_MODEL_NAME = "Qwen2.5-0.5B-Instruct-q8.task"
    private const val ORIGINAL_HF_MODEL_NAME =
        "Qwen2.5-0.5B-Instruct_multi-prefill-seq_q8_ekv1280.task"

    fun modelDir(context: Context): File =
        File(context.filesDir, "ai_model").apply { if (!exists()) mkdirs() }

    fun modelFile(context: Context): File? =
        modelDir(context).listFiles()?.firstOrNull { it.name.endsWith(".task") }

    /** Real install check: file present, the known-good package, and
     *  plausibly complete. Foreign/stale .task files are DELETED here —
     *  self-healing against variants that crash the native runtime. */
    fun isInstalled(context: Context): Boolean {
        val candidates = modelDir(context).listFiles()
            ?.filter { it.name.endsWith(".task") }
            ?: return false
        var good = false
        for (f in candidates) {
            val knownGood = f.name in setOf(KNOWN_MODEL_NAME, ORIGINAL_HF_MODEL_NAME) &&
                f.length() in (EXPECTED_BYTES * 98 / 100)..(EXPECTED_BYTES * 102 / 100)
            if (knownGood) {
                good = true
            } else {
                Log.w(TAG, "Quarantining incompatible model file: ${f.name} (${f.length()} bytes)")
                LocalLlmRuntime.release()
                f.delete()
            }
        }
        return good
    }

    fun installedSizeBytes(context: Context): Long = modelFile(context)?.length() ?: 0L

    fun freeSpaceBytes(context: Context): Long =
        StatFs(context.filesDir.absolutePath).availableBytes

    data class InstallState(
        val idle: Boolean = true,
        val downloading: Boolean = false,
        val progress: Int = 0,          // 0..100
        val error: String? = null
    )

    private val _state = MutableStateFlow(InstallState())
    val state: StateFlow<InstallState> = _state

    /**
     * Download the model into app-private storage with live progress.
     * Verifies minimum size before marking installed.
     */
    suspend fun install(context: Context) = withContext(Dispatchers.IO) {
        if (isInstalled(context)) {
            _state.value = InstallState(idle = true, progress = 100)
            return@withContext
        }
        _state.value = InstallState(idle = false, downloading = true, progress = 0)
        try {
            val dir = modelDir(context)
            val tmp = File(dir, "model.task.part")
            val conn = URL(MODEL_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = 20_000
            conn.readTimeout = 60_000
            conn.instanceFollowRedirects = true
            conn.connect()

            val total = conn.contentLengthLong.takeIf { it > 0 } ?: EXPECTED_BYTES
            conn.inputStream.use { input ->
                tmp.outputStream().use { out ->
                    val buf = ByteArray(1 shl 16)
                    var copied = 0L
                    while (true) {
                        if (_state.value.error != null) throw IOException("Cancelled")
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        copied += n
                        val pct = ((copied * 100) / total).toInt().coerceIn(0, 100)
                        if (pct != _state.value.progress) {
                            _state.value = _state.value.copy(progress = pct)
                        }
        }
                }
            }

            if (tmp.length() < EXPECTED_BYTES * 9 / 10) {
                tmp.delete()
                throw IOException("Download incomplete (${tmp.length()} bytes)")
            }
            val final = File(dir, "Qwen2.5-0.5B-Instruct-q8.task")
            if (final.exists()) final.delete()
            if (!tmp.renameTo(final)) throw IOException("Rename failed")
            // Clean any stale stubs from earlier failed attempts.
            dir.listFiles()?.filter { it.name.endsWith(".part") }?.forEach { it.delete() }

            SettingsStore(context).setAiModelInstalled(true)
            SettingsStore(context).setAiModelSize(final.length())
            SettingsStore(context).setScannerLlmCrashes(0) // fresh model — reopen the circuit
            _state.value = InstallState(idle = true, progress = 100)
            Log.i(TAG, "Model installed: ${final.length()} bytes")
        } catch (t: Throwable) {
            Log.e(TAG, "install failed", t)
            _state.value = InstallState(idle = true, error = t.message ?: "Download failed")
        }
    }

    /** Delete the model file; security scanning is unaffected (spec §20). */
    suspend fun delete(context: Context) = withContext(Dispatchers.IO) {
        LocalLlmRuntime.release()
        modelFile(context)?.delete()
        SettingsStore(context).setAiModelInstalled(false)
        SettingsStore(context).setAiModelSize(0)
        SettingsStore(context).setScannerLlmCrashes(0) // clean slate for the next install
    }
}
