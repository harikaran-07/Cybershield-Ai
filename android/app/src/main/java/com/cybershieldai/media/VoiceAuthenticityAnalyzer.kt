package com.cybershieldai.media

/**
 * VoiceAuthenticityAnalyzer (spec §4) — deterministic, on-device audio
 * forensics. No ML model, no network, no call-audio: the user picks a file
 * and the analyzer decodes a bounded sample window with Android's MediaCodec
 * and measures spectral/statistical signals associated with synthetic
 * speech generation.
 *
 * Signals measured (each becomes evidence, never a verdict):
 *  - Spectral flatness of voiced regions: TTS engines produce unnaturally
 *    smooth harmonic stacks; human phonation breathes.
 *  - High-band energy ratio: neural vocoders historically under-populate
 *    >7.5 kHz content; recordings carry it.
 *  - Pause regularity: neural TTS inter-phrase silences are suspiciously
 *    uniform vs. human hesitation.
 *  - Phase/texture noise floor: vocoder artifacts show as unusually low
 *    noise floor between harmonics.
 */
object VoiceAuthenticityAnalyzer {

    private const val MAX_DECODED_SECONDS = 30.0

    fun analyze(context: android.content.Context, uri: android.net.Uri): MediaSecurityResult {
        val limitations = mutableListOf(
            "Automated detection can produce false positives and false negatives",
            "Compressed or noisy recordings reduce detection reliability"
        )
        val findings = mutableListOf<String>()
        val indicators = mutableListOf<MediaRiskEngine.Indicator>()
        val extractor = android.media.MediaExtractor()
        try {
            context.contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                extractor.setDataSource(pfd.fileDescriptor)
            } ?: return failed("The audio file could not be opened.")
            var trackIndex = -1
            var format: android.media.MediaFormat? = null
            for (i in 0 until extractor.trackCount) {
                val f = extractor.getTrackFormat(i)
                if (f.getString(android.media.MediaFormat.KEY_MIME)?.startsWith("audio/") == true) {
                    trackIndex = i; format = f; break
                }
            }
            if (trackIndex < 0 || format == null) {
                return MediaSecurityResult(
                    "AUDIO", MediaSecurityResult.Status.INCONCLUSIVE, "LOW", 0,
                    emptyList(), listOf("No decodable audio track found"),
                    limitations + "The container has no audio track this device can decode",
                    MediaRiskEngine.recommendationFor(MediaSecurityResult.Status.INCONCLUSIVE, "audio")
                )
            }
            extractor.selectTrack(trackIndex)
            val mime = format.getString(android.media.MediaFormat.KEY_MIME)!!
            val sampleRate = format.getInteger(android.media.MediaFormat.KEY_SAMPLE_RATE)
            val channels = format.getInteger(android.media.MediaFormat.KEY_CHANNEL_COUNT)
            val durationUs = if (format.containsKey(android.media.MediaFormat.KEY_DURATION))
                format.getLong(android.media.MediaFormat.KEY_DURATION) else 0L

            // ---- Decode a bounded window to PCM (mono, first N seconds) ----
            val pcm = VoiceAuthenticityAnalyzerInternal.decodeWindow(
                extractor, mime, sampleRate, channels)
            if (pcm == null || pcm.samples.isEmpty()) {
                return MediaSecurityResult(
                    "AUDIO", MediaSecurityResult.Status.INCONCLUSIVE, "LOW", 0,
                    emptyList(), listOf("Container: $mime, ${sampleRate}Hz, ${channels}ch"),
                    limitations + "PCM decoding failed on this device codec",
                    MediaRiskEngine.recommendationFor(MediaSecurityResult.Status.INCONCLUSIVE, "audio"))
            }
            findings.add("Container: $mime · ${sampleRate}Hz · ${channels}ch")
            if (durationUs > 0) {
                findings.add(String.format(java.util.Locale.US,
                    "Duration: %.1f s (analyzed first %.0f s)",
                    durationUs / 1_000_000.0, pcm.analyzedSeconds))
                if (durationUs > (MAX_DECODED_SECONDS * 1_000_000).toLong()) {
                    limitations.add("Only the first ${MAX_DECODED_SECONDS.toInt()} seconds were analyzed")
                }
            }

            // ---- Signal 1: spectral flatness (voiced-band smoothness) ----
            val flatness = VoiceAuthenticityAnalyzerInternal.spectralFlatness(pcm.samples, pcm.sampleRate)
            findings.add(String.format(java.util.Locale.US,
                "Spectral flatness (voiced band): %.3f", flatness))
            // Human voiced speech ≈ 0.05–0.35; neural TTS tends lower (very smooth).
            if (flatness < 0.045) {
                indicators += MediaRiskEngine.Indicator(
                    "Unusually smooth spectral texture",
                    strength = ((0.045 - flatness) / 0.045).coerceIn(0.15, 0.75),
                    detail = String.format(java.util.Locale.US,
                        "Voiced-band flatness %.3f is below the typical recorded-speech range", flatness))
            }

            // ---- Signal 2: high-band energy ratio (>7.5 kHz) ----
            val hf = VoiceAuthenticityAnalyzerInternal.highBandRatio(pcm.samples, pcm.sampleRate)
            findings.add(String.format(java.util.Locale.US,
                "High-band (>7.5 kHz) energy ratio: %.4f", hf))
            if (sampleRate >= 32000 && hf < 0.004) {
                indicators += MediaRiskEngine.Indicator(
                    "Under-populated high-frequency band",
                    strength = 0.35,
                    detail = String.format(java.util.Locale.US,
                        "Only %.2f%% of spectral energy above 7.5 kHz — consistent with some synthetic sources", hf * 100))
            }

            // ---- Signal 3: silence/pause uniformity ----
            val pause = VoiceAuthenticityAnalyzerInternal.pauseUniformity(pcm.samples, pcm.sampleRate)
            findings.add(String.format(java.util.Locale.US,
                "Pause uniformity index: %.3f over %d pauses", pause.first, pause.second))
            if (pause.second >= 3 && pause.first < 0.08) {
                indicators += MediaRiskEngine.Indicator(
                    "Machine-like pause regularity",
                    strength = ((0.08 - pause.first) / 0.08).coerceIn(0.2, 0.7),
                    detail = String.format(java.util.Locale.US,
                        "Inter-phrase silences vary by only %.0f%% (human speech varies more)", pause.first * 100))
            }

            // ---- Signal 4: noise floor between harmonics ----
            val noiseFloor = VoiceAuthenticityAnalyzerInternal.betweenHarmonicNoise(pcm.samples, pcm.sampleRate)
            findings.add(String.format(java.util.Locale.US,
                "Inter-harmonic noise floor: %.4f", noiseFloor))
            if (noiseFloor < 0.0006) {
                indicators += MediaRiskEngine.Indicator(
                    "Synthetic-silence texture between harmonics",
                    strength = 0.3,
                    detail = String.format(java.util.Locale.US,
                        "Inter-harmonic noise %.4f is lower than typical room+mic noise", noiseFloor))
            }

            val (confidence, status) = MediaRiskEngine.assess(indicators, limitations, "audio")
            return MediaSecurityResult(
                mediaType = "AUDIO",
                status = status,
                riskLevel = MediaRiskEngine.riskLevelFor(confidence),
                confidence = confidence,
                indicators = indicators.sortedByDescending { it.strength }
                    .map { "${it.label} — ${it.detail}" },
                technicalFindings = findings,
                limitations = limitations,
                recommendation = MediaRiskEngine.recommendationFor(status, "recording")
            )
        } catch (_: Exception) {
            return failed("The audio could not be decoded — the file may be corrupted or use an unsupported codec.")
        } finally {
            try { extractor.release() } catch (_: Exception) {}
        }
    }

    private fun failed(msg: String) = MediaSecurityResult(
        "AUDIO", MediaSecurityResult.Status.ANALYSIS_FAILED, "LOW", 0,
        emptyList(), emptyList(), listOf(msg),
        MediaRiskEngine.recommendationFor(MediaSecurityResult.Status.ANALYSIS_FAILED, "audio"))
}

/**
 * Internal DSP/decode core. Shared with the video pipeline through the
 * bridge objects in VideoAuthenticityAnalyzer.kt so both analyzers measure
 * audio identically. `internal` = module-visible only.
 */
internal object VoiceAuthenticityAnalyzerInternal {

    private const val MAX_DECODED_SECONDS = 30.0

    class PcmData(val samples: ShortArray, val sampleRate: Int, val analyzedSeconds: Double)

    // ------------------------------------------------------------------
    // Bounded PCM decode via MediaCodec (first N seconds, mono downmix)
    // ------------------------------------------------------------------
    fun decodeWindow(
        extractor: android.media.MediaExtractor, mime: String, sampleRate: Int, channels: Int
    ): PcmData? {
        val codec = android.media.MediaCodec.createDecoderByType(mime)
        try {
            codec.configure(extractor.getTrackFormat(extractor.sampleTrackIndex), null, null, 0)
            codec.start()
            val target = (sampleRate * MAX_DECODED_SECONDS).toInt()
            val out = ShortArray(target)
            var filled = 0
            var inputEos = false
            val info = android.media.MediaCodec.BufferInfo()
            val deadline = System.currentTimeMillis() + 20_000L
            while (filled < target && !inputEos && System.currentTimeMillis() < deadline) {
                if (!inputEos) {
                    val inIdx = codec.dequeueInputBuffer(10_000)
                    if (inIdx >= 0) {
                        val buf = codec.getInputBuffer(inIdx)!!
                        val n = extractor.readSampleData(buf, 0)
                        if (n < 0) {
                            codec.queueInputBuffer(
                                inIdx, 0, 0, 0, android.media.MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                            inputEos = true
                        } else {
                            codec.queueInputBuffer(inIdx, 0, n, extractor.sampleTime, 0)
                            extractor.advance()
                        }
                    }
                }
                val outIdx = codec.dequeueOutputBuffer(info, 10_000)
                if (outIdx >= 0) {
                    val buf = codec.getOutputBuffer(outIdx)!!
                    buf.order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    val shorts = ShortArray(info.size / 2)
                    buf.asShortBuffer().get(shorts)
                    // Downmix to mono (average channels).
                    val ch = channels.coerceAtLeast(1)
                    val frames = shorts.size / ch
                    var i = 0
                    while (i < frames && filled < target) {
                        var acc = 0L
                        for (c in 0 until ch) acc += shorts[i * ch + c].toInt()
                        out[filled++] = (acc / ch).toShort()
                        i++
                    }
                    codec.releaseOutputBuffer(outIdx, false)
                } else if (outIdx == android.media.MediaCodec.INFO_TRY_AGAIN_LATER && inputEos) {
                    break
                }
            }
            return if (filled > 0)
                PcmData(out.copyOf(filled), sampleRate, filled / sampleRate.toDouble())
            else null
        } catch (_: Exception) {
            return null
        } finally {
            try { codec.stop() } catch (_: Exception) {}
            try { codec.release() } catch (_: Exception) {}
        }
    }

    // ------------------------------------------------------------------
    // DSP measurements (deterministic, pure math over the decoded PCM)
    // ------------------------------------------------------------------

    /** Mean spectral flatness over 1024-pt Hann-windowed FFTs in the voiced band. */
    fun spectralFlatness(samples: ShortArray, sr: Int): Double {
        val frame = 1024
        val hop = 2048
        if (samples.size < frame) return 0.5
        val flats = mutableListOf<Double>()
        var f = 0
        while (f + frame <= samples.size) {
            val re = DoubleArray(frame); val im = DoubleArray(frame)
            for (i in 0 until frame) {
                val w = 0.5 - 0.5 * Math.cos(2.0 * Math.PI * i / (frame - 1))
                re[i] = (samples[f + i] / 32768.0) * w
            }
            fft(re, im)
            var logSum = 0.0; var linSum = 0.0; var bins = 0
            val loBin = (85.0 / sr * frame).toInt().coerceAtLeast(1)               // 85 Hz
            val hiBin = (4000.0 / sr * frame).toInt().coerceAtMost(frame / 2 - 1)  // 4 kHz
            for (k in loBin..hiBin) {
                val mag = Math.hypot(re[k], im[k]) + 1e-12
                logSum += Math.log(mag); linSum += mag; bins++
            }
            if (bins > 0) flats.add(Math.exp(logSum / bins) / (linSum / bins))
            f += hop
        }
        if (flats.isEmpty()) return 0.5
        return flats.sorted()[flats.size / 2] // median frame
    }

    /** Fraction of total spectral energy above 7.5 kHz. */
    fun highBandRatio(samples: ShortArray, sr: Int): Double {
        val frame = 2048
        if (samples.size < frame) return 0.0
        val re = DoubleArray(frame); val im = DoubleArray(frame)
        val off = samples.size / 2 - frame / 2
        for (i in 0 until frame) {
            val w = 0.5 - 0.5 * Math.cos(2.0 * Math.PI * i / (frame - 1))
            re[i] = (samples[off + i] / 32768.0) * w
        }
        fft(re, im)
        var total = 0.0; var hi = 0.0
        for (k in 1 until frame / 2) {
            val mag2 = re[k] * re[k] + im[k] * im[k]
            total += mag2
            if (k * sr.toDouble() / frame > 7500.0) hi += mag2
        }
        return if (total > 0) hi / total else 0.0
    }

    /** CV (std/mean) of silence-pause lengths between speech segments. */
    fun pauseUniformity(samples: ShortArray, sr: Int): Pair<Double, Int> {
        val win = (sr / 50).coerceAtLeast(1) // 20 ms RMS windows
        if (samples.size < win * 10) return 0.5 to 0
        val frames = samples.size / win
        val rms = DoubleArray(frames)
        for (i in 0 until frames) {
            var acc = 0.0
            for (j in 0 until win) acc += samples[i * win + j].toDouble() * samples[i * win + j]
            rms[i] = Math.sqrt(acc / win)
        }
        var peak = rms.max()
        if (peak <= 0.0) return 0.5 to 0
        peak *= 0.06 // silence threshold: 6% of peak RMS
        val isSil = BooleanArray(frames) { rms[it] < peak }
        val pauses = mutableListOf<Int>()
        var run = 0
        for (i in 0 until frames) {
            if (isSil[i]) run++
            else {
                if (run in 3..60) pauses.add(run) // 60–1200 ms silence runs
                run = 0
            }
        }
        if (pauses.size < 2) return 0.5 to pauses.size
        val mean = pauses.average()
        val varr = pauses.sumOf { (it - mean) * (it - mean) } / pauses.size
        val cv = if (mean > 0) Math.sqrt(varr) / mean else 0.5
        return cv to pauses.size
    }

    /** Median noise energy in bins between strong harmonics (300–3400 Hz). */
    fun betweenHarmonicNoise(samples: ShortArray, sr: Int): Double {
        val frame = 2048
        if (samples.size < frame) return 0.0
        val re = DoubleArray(frame); val im = DoubleArray(frame)
        val off = samples.size / 4 - frame / 2
        for (i in 0 until frame) {
            val w = 0.5 - 0.5 * Math.cos(2.0 * Math.PI * i / (frame - 1))
            re[i] = (samples[off.coerceAtLeast(0) + i] / 32768.0) * w
        }
        fft(re, im)
        val mags = DoubleArray(frame / 2) { Math.hypot(re[it], im[it]) }
        var valleySum = 0.0; var valleys = 0
        val lo = (300.0 / sr * frame).toInt().coerceAtLeast(3)
        val hi = (3400.0 / sr * frame).toInt().coerceAtMost(frame / 2 - 3)
        for (k in lo..hi) {
            val localAvg = (mags[k - 3] + mags[k - 2] + mags[k - 1] +
                mags[k + 1] + mags[k + 2] + mags[k + 3]) / 6.0
            val isPeak = mags[k] > mags[k - 1] && mags[k] > mags[k + 1] &&
                mags[k] > 8 * localAvg
            if (isPeak) {
                valleySum += (mags[k - 2] + mags[k + 2]) / 2.0
                valleys++
            }
        }
        val peakEnergy = mags.sum().coerceAtLeast(1e-9)
        return if (valleys > 0) (valleySum / valleys) / peakEnergy else 0.005
    }

    // ---- Minimal in-place radix-2 FFT (iterative Cooley–Tukey) ----
    private fun fft(re: DoubleArray, im: DoubleArray) {
        val n = re.size
        var j = 0
        for (i in 1 until n) {
            var bit = n shr 1
            while (j and bit != 0) { j = j xor bit; bit = bit shr 1 }
            j = j or bit
            if (i < j) {
                val tr = re[i]; re[i] = re[j]; re[j] = tr
                val ti = im[i]; im[i] = im[j]; im[j] = ti
            }
        }
        var len = 2
        while (len <= n) {
            val ang = -2.0 * Math.PI / len
            val wr = Math.cos(ang); val wi = Math.sin(ang)
            var i = 0
            while (i < n) {
                var cr = 1.0; var ci = 0.0
                for (k in 0 until len / 2) {
                    val ur = re[i + k]; val ui = im[i + k]
                    val vr = re[i + k + len / 2] * cr - im[i + k + len / 2] * ci
                    val vi = re[i + k + len / 2] * ci + im[i + k + len / 2] * cr
                    re[i + k] = ur + vr; im[i + k] = ui + vi
                    re[i + k + len / 2] = ur - vr; im[i + k + len / 2] = ui - vi
                    val ncr = cr * wr - ci * wi
                    ci = cr * wi + ci * wr; cr = ncr
                }
                i += len
            }
            len = len shl 1
        }
    }
}
