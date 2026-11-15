package com.hicar.explorer.media

import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaRecorder
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicBoolean

/**
 * MicRecorder - Virtual Microphone (VirMic) audio capture engine for HiCar / DMSDP.
 *
 * Captures audio from the physical microphone, encodes it into AAC-LC with ADTS headers
 * (as required by Huawei HiCar DMSDP FDK AAC decoder), and delivers real-time frames
 * to the DMSDP data channel.
 *
 * Fully compatible with Android 4.4 (KitKat, API 19) through Android 15.
 */
class MicRecorder(private val context: Context) {

    companion object {
        private const val TAG = "MicRecorder"
        const val DEFAULT_SAMPLE_RATE = 16000
        const val HD_SAMPLE_RATE = 48000
    }

    interface Callback {
        fun onAudioFrame(dataSessionId: Int, pcmData: ByteArray, offset: Int, length: Int)
        fun onRecordingStateChanged(isRecording: Boolean, reason: String)
    }

    var callback: Callback? = null

    private var audioRecord: AudioRecord? = null
    private var aacEncoder: MediaCodec? = null
    private var recordThread: Thread? = null
    private val isRecording = AtomicBoolean(false)
    private var currentSessionId: Int = 0

    /**
     * Start microphone recording for a given DMSDP DataSessionID.
     *
     * @param dataSessionId The session identifier from the phone's SET_PARAMETER
     * @param sampleRate Requested sample rate (typically 48000 or 16000)
     * @param channelCount 2 for stereo, 1 for mono
     * @param codec 0 for AAC-LC (Huawei HiCar standard), 1 for raw PCM
     */
    @Synchronized
    fun startRecording(
        dataSessionId: Int,
        sampleRate: Int = DEFAULT_SAMPLE_RATE,
        channelCount: Int = 1,
        codec: Int = 0
    ) {
        if (isRecording.get()) {
            if (currentSessionId == dataSessionId) {
                Log.d(TAG, "Already recording for session $dataSessionId")
                return
            }
            stopRecording()
        }

        // Check RECORD_AUDIO permission
        if (ContextCompat.checkSelfPermission(context, android.Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED) {
            Log.e(TAG, "Cannot start recording: RECORD_AUDIO permission not granted!")
            callback?.onRecordingStateChanged(false, "Microphone permission not granted")
            return
        }

        currentSessionId = dataSessionId

        val channelConfig = if (channelCount == 1) {
            AudioFormat.CHANNEL_IN_MONO
        } else {
            AudioFormat.CHANNEL_IN_STEREO
        }
        val audioFormat = AudioFormat.ENCODING_PCM_16BIT
        val bytesPerSample = 2 // 16-bit PCM = 2 bytes

        // For AAC input: 20ms chunks are ideal
        val chunkDurationMs = 20
        val chunkSize = (sampleRate * channelCount * bytesPerSample * chunkDurationMs) / 1000

        val minBufSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat)
        if (minBufSize <= 0) {
            Log.e(TAG, "AudioRecord minBufferSize invalid ($minBufSize) for $sampleRate Hz, channels=$channelCount")
            callback?.onRecordingStateChanged(false, "AudioRecord config unsupported")
            return
        }

        val internalBufferSize = maxOf(minBufSize * 2, chunkSize * 4)

        // Try VOICE_RECOGNITION source first (enables hardware AGC & noise suppressor), fallback to MIC
        var record: AudioRecord? = null
        val sources = intArrayOf(
            MediaRecorder.AudioSource.VOICE_RECOGNITION,
            MediaRecorder.AudioSource.MIC
        )

        for (source in sources) {
            try {
                val candidate = AudioRecord(source, sampleRate, channelConfig, audioFormat, internalBufferSize)
                if (candidate.state == AudioRecord.STATE_INITIALIZED) {
                    record = candidate
                    Log.i(TAG, "AudioRecord initialized successfully with source=$source, rate=$sampleRate, channels=$channelCount, chunk=$chunkSize B")
                    break
                } else {
                    candidate.release()
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to initialize AudioRecord with source=$source: ${e.message}")
            }
        }

        if (record == null) {
            Log.e(TAG, "Failed to initialize any AudioRecord candidate")
            callback?.onRecordingStateChanged(false, "AudioRecord initialization failed")
            return
        }

        // Initialize MediaCodec AAC-LC encoder if codec == 0
        var encoder: MediaCodec? = null
        if (codec == 0) {
            try {
                val aacBitrate = if (channelCount == 1) 64000 else 128000
                val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_AAC, sampleRate, channelCount).apply {
                    setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectLC)
                    setInteger(MediaFormat.KEY_BIT_RATE, aacBitrate)
                    setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 16384)
                }
                val candidate = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_AAC)
                candidate.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
                candidate.start()
                encoder = candidate
                Log.i(TAG, "AAC Encoder initialized: $sampleRate Hz, channels=$channelCount, bitrate=$aacBitrate")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize AAC encoder: ${e.message}. Falling back to PCM.", e)
            }
        }
        aacEncoder = encoder

        try {
            record.startRecording()
        } catch (e: Exception) {
            Log.e(TAG, "startRecording failed: ${e.message}")
            record.release()
            try { encoder?.release() } catch (_: Exception) {}
            aacEncoder = null
            callback?.onRecordingStateChanged(false, "startRecording exception")
            return
        }

        audioRecord = record
        isRecording.set(true)
        val modeStr = if (encoder != null) "AAC-LC" else "PCM"
        callback?.onRecordingStateChanged(true, "Recording: $sampleRate Hz ${if (channelCount == 2) "Stereo" else "Mono"} ($modeStr)")

        // Background capture loop
        recordThread = Thread({
            Log.i(TAG, "🎙️ Mic capture loop started (session=$dataSessionId, chunkSize=$chunkSize, mode=$modeStr)")
            val buffer = ByteArray(chunkSize)
            var totalBytesRead = 0L
            var totalBytesSent = 0L
            var frameCount = 0
            val bufferInfo = MediaCodec.BufferInfo()

            while (isRecording.get()) {
                val read = record.read(buffer, 0, chunkSize)
                if (read > 0) {
                    totalBytesRead += read

                    // Apply digital gain (5.0x boost) with saturation clamping to ensure clear voice recognition
                    val digitalGain = 5.0f
                    var maxAmp = 0
                    for (i in 0 until read - 1 step 2) {
                        val low = buffer[i].toInt() and 0xFF
                        val high = buffer[i + 1].toInt()
                        val originalSample = (high shl 8) or low
                        var boosted = (originalSample.toShort() * digitalGain).toInt()
                        if (boosted > 32767) boosted = 32767
                        else if (boosted < -32768) boosted = -32768
                        buffer[i] = (boosted and 0xFF).toByte()
                        buffer[i + 1] = ((boosted shr 8) and 0xFF).toByte()

                        val abs = Math.abs(boosted)
                        if (abs > maxAmp) maxAmp = abs
                    }

                    if (encoder != null) {
                        // Feed raw PCM into MediaCodec AAC Encoder
                        try {
                            val inIndex = encoder.dequeueInputBuffer(10000L)
                            if (inIndex >= 0) {
                                @Suppress("DEPRECATION")
                                val inBuffer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                                    encoder.getInputBuffer(inIndex)
                                } else {
                                    encoder.inputBuffers[inIndex]
                                }
                                inBuffer?.clear()
                                inBuffer?.put(buffer, 0, read)
                                val ptsUs = System.nanoTime() / 1000L
                                encoder.queueInputBuffer(inIndex, 0, read, ptsUs, 0)
                            }

                            // Drain encoded AAC frames
                            while (isRecording.get()) {
                                val outIndex = encoder.dequeueOutputBuffer(bufferInfo, 0L)
                                if (outIndex >= 0) {
                                    // Skip CSD codec-config headers
                                    if ((bufferInfo.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG) != 0) {
                                        encoder.releaseOutputBuffer(outIndex, false)
                                        continue
                                    }
                                    @Suppress("DEPRECATION")
                                    val outBuffer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                                        encoder.getOutputBuffer(outIndex)
                                    } else {
                                        encoder.outputBuffers[outIndex]
                                    }
                                    if (outBuffer != null && bufferInfo.size > 0) {
                                        val aacData = ByteArray(bufferInfo.size)
                                        outBuffer.position(bufferInfo.offset)
                                        outBuffer.get(aacData, 0, bufferInfo.size)

                                        // Prepend standard 7-byte ADTS header for Huawei FDK AAC decoder
                                        val adtsPacket = ByteArray(7 + aacData.size)
                                        addAdtsHeader(adtsPacket, adtsPacket.size, sampleRate, channelCount)
                                        System.arraycopy(aacData, 0, adtsPacket, 7, aacData.size)

                                        frameCount++
                                        totalBytesSent += adtsPacket.size
                                        callback?.onAudioFrame(dataSessionId, adtsPacket, 0, adtsPacket.size)

                                        if (frameCount <= 5 || frameCount % 50 == 0) {
                                            Log.d(TAG, "🎙️ TX Mic AAC frame #$frameCount (${adtsPacket.size} B, maxAmp=$maxAmp, total=$totalBytesSent B)")
                                        }
                                    }
                                    encoder.releaseOutputBuffer(outIndex, false)
                                } else {
                                    break
                                }
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "Error encoding AAC: ${e.message}")
                        }
                    } else {
                        // Raw PCM fallback
                        frameCount++
                        totalBytesSent += read
                        callback?.onAudioFrame(dataSessionId, buffer, 0, read)
                        if (frameCount <= 5 || frameCount % 50 == 0) {
                            Log.d(TAG, "🎙️ TX Mic PCM frame #$frameCount ($read B, maxAmp=$maxAmp, total=$totalBytesSent B)")
                        }
                    }
                } else if (read < 0) {
                    Log.w(TAG, "AudioRecord read returned error code: $read")
                    if (!isRecording.get()) break
                    try { Thread.sleep(10) } catch (_: InterruptedException) { break }
                }
            }
            Log.i(TAG, "🎙️ Mic capture loop stopped (total $frameCount frames, sent $totalBytesSent B, read $totalBytesRead B)")
        }, "HiCar-MicRecordThread").apply {
            priority = Thread.MAX_PRIORITY
            start()
        }
    }

    /**
     * Prepend standard 7-byte ADTS header to an AAC packet.
     */
    private fun addAdtsHeader(packet: ByteArray, packetLen: Int, sampleRate: Int, channels: Int) {
        val profile = 2 // AAC-LC (MPEG-4 Audio Object Type 2)
        val freqIdx = when (sampleRate) {
            96000 -> 0
            88200 -> 1
            64000 -> 2
            48000 -> 3
            44100 -> 4
            32000 -> 5
            24000 -> 6
            22050 -> 7
            16000 -> 8
            12000 -> 9
            11025 -> 10
            8000 -> 11
            7350 -> 12
            else -> 3
        }
        val chanCfg = channels // 1 or 2

        packet[0] = 0xFF.toByte()
        packet[1] = 0xF9.toByte() // MPEG-4, Layer 0, No protection (1)
        packet[2] = (((profile - 1) shl 6) or (freqIdx shl 2) or ((chanCfg shr 2) and 1)).toByte()
        packet[3] = (((chanCfg and 3) shl 6) or ((packetLen shr 11) and 3)).toByte()
        packet[4] = ((packetLen shr 3) and 0xFF).toByte()
        packet[5] = (((packetLen and 7) shl 5) or 0x1F).toByte()
        packet[6] = 0xFC.toByte()
    }

    /**
     * Stop microphone recording and release resources.
     */
    @Synchronized
    fun stopRecording() {
        if (!isRecording.getAndSet(false)) return

        Log.i(TAG, "Stopping Mic recording...")
        try {
            recordThread?.interrupt()
            recordThread = null
        } catch (_: Exception) {}

        try {
            audioRecord?.stop()
            audioRecord?.release()
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping AudioRecord: ${e.message}")
        }
        audioRecord = null

        try {
            aacEncoder?.stop()
            aacEncoder?.release()
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping AAC encoder: ${e.message}")
        }
        aacEncoder = null

        callback?.onRecordingStateChanged(false, "Stopped")
    }

    fun isRecording(): Boolean = isRecording.get()
}
