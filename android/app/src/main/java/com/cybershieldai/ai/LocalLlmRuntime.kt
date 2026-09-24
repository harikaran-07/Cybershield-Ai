package com.cybershieldai.ai

import android.content.Context
import android.util.Log
import com.google.mediapipe.tasks.genai.llminference.LlmInference
import com.google.mediapipe.tasks.genai.llminference.LlmInferenceSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.withContext

/**
 * On-device LLM runtime (spec §2/§3): wraps MediaPipe tasks-genai `LlmInference`
 * running the installed Qwen2.5-0.5B .task model 100% on-device — no cloud, no
 * API key, no localhost, no WebView (spec §1). Created lazily when the chat
 * opens; released when the chat screen leaves (spec §21).
 */
object LocalLlmRuntime {

    private const val TAG = "CyberShieldLlm"

    @Volatile private var engine: LlmInference? = null
    @Volatile private var loadedFile: String? = null

    /** True while the model file is resident in memory. */
    fun isLoaded(): Boolean = engine != null

    /**
     * Load the model if needed. Safe to call repeatedly — a no-op when the
     * same file is already resident (spec §21: don't reload per message).
     * Tries the GPU backend first, falls back to CPU.
     */
    suspend fun load(context: Context): Result<Unit> = withContext(Dispatchers.IO) {
        val path = AiModelManager.modelFile(context)?.absolutePath
            ?: return@withContext Result.failure(IllegalStateException("Model not installed"))

        if (engine != null && loadedFile == path) return@withContext Result.success(Unit)

        release()
        // CPU-first (spec §21 low-end safety): the CPU graph works on every
        // device including emulators and low-RAM phones; the GPU delegate can
        // hard-crash (SIGSEGV) where OpenCL is unavailable. GPU is only tried
        // when CPU loading fails.
        val cpu = tryLoad(context, path, LlmInference.Backend.CPU)
        if (cpu.isSuccess) {
            loadedFile = path
            Log.i(TAG, "LLM loaded (CPU) from $path")
            return@withContext cpu
        }
        // Fallback: GPU.
        val gpu = tryLoad(context, path, LlmInference.Backend.GPU)
        if (gpu.isSuccess) {
            loadedFile = path
            Log.i(TAG, "LLM loaded (GPU) from $path")
        } else {
            Log.e(TAG, "LLM load failed on both backends")
        }
        gpu
    }

    private fun tryLoad(
        context: Context,
        path: String,
        backend: LlmInference.Backend
    ): Result<Unit> = try {
        release()
        val options = LlmInference.LlmInferenceOptions.builder()
            .setModelPath(path)
            .setMaxTokens(1024)
            .setPreferredBackend(backend)
            .build()
        engine = LlmInference.createFromOptions(context, options)
        Result.success(Unit)
    } catch (t: Throwable) {
        Log.w(TAG, "load with $backend failed: ${t.message}")
        release()
        Result.failure(t)
    }

    /**
     * Stream one completion. Cancelling the collecting coroutine (or calling
     * [CyberShieldChat.stop]) cancels generation inside MediaPipe.
     */
    fun generate(prompt: String): Flow<String> = callbackFlow {
        val llm = engine
        if (llm == null) {
            close(IllegalStateException("Model not loaded"))
            return@callbackFlow
        }
        var session: LlmInferenceSession? = null
        try {
            val s = LlmInferenceSession.createFromOptions(
                llm,
                LlmInferenceSession.LlmInferenceSessionOptions.builder()
                    .setTemperature(0.4f)
                    .setTopK(40)
                    .setTopP(0.95f)
                    .build()
            )
            session = s
            s.addQueryChunk(prompt)
            s.generateResponseAsync { partial: String?, done: Boolean ->
                if (!partial.isNullOrEmpty()) trySend(partial)
                if (done) close()
            }
        } catch (t: Throwable) {
            Log.e(TAG, "generation error", t)
            close(t)
        }
        awaitClose {
            try { session?.cancelGenerateResponseAsync() } catch (_: Throwable) {}
            try { session?.close() } catch (_: Throwable) {}
        }
    }

    /** Free model memory. Called when the chat screen is disposed. */
    fun release() {
        try {
            engine?.close()
        } catch (_: Throwable) {}
        engine = null
        loadedFile = null
    }
}
