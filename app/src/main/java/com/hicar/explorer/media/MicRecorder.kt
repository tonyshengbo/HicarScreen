package com.hicar.explorer.media

import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicBoolean

/**
 * MicRecorder - Virtual Microphone (VirMic) audio capture engine for HiCar / DMSDP.
 *
 * Captures raw PCM audio from the car device's physical microphone and delivers
 * real-time 20ms audio chunks to the DMSDP data channel.
 *
 * Fully compatible with Android 4.4 (KitKat, API 19) through Android 15.
 */
class MicRecorder(private val context: Context) {

    companion object {
        private const val TAG = "MicRecorder"
        const val DEFAULT_SAMPLE_RATE = 48000
        const val VOICE_SAMPLE_RATE = 16000
    }

    interface Callback {
        fun onAudioFrame(dataSessionId: Int, pcmData: ByteArray, offset: Int, length: Int)
        fun onRecordingStateChanged(isRecording: Boolean, reason: String)
    }

    var callback: Callback? = null

    private var audioRecord: AudioRecord? = null
    private var recordThread: Thread? = null
    private val isRecording = AtomicBoolean(false)
    private var currentSessionId: Int = 0

    /**
     * Start microphone recording for a given DMSDP DataSessionID.
     *
     * @param dataSessionId The session identifier from the phone's SET_PARAMETER
     * @param sampleRate Requested sample rate (typically 48000 or 16000)
     * @param channelCount 2 for stereo, 1 for mono
     */
    @Synchronized
    fun startRecording(dataSessionId: Int, sampleRate: Int = DEFAULT_SAMPLE_RATE, channelCount: Int = 2) {
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

        // Calculate 20ms chunk size
        // e.g., 48000 * 2 channels * 2 bytes * 0.02s = 3840 bytes
        // e.g., 16000 * 1 channel  * 2 bytes * 0.02s = 640 bytes
        val chunkSize = (sampleRate * channelCount * bytesPerSample * 20) / 1000

        val minBufSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat)
        if (minBufSize <= 0) {
            Log.e(TAG, "AudioRecord minBufferSize invalid ($minBufSize) for $sampleRate Hz, channels=$channelCount")
            callback?.onRecordingStateChanged(false, "AudioRecord config unsupported")
            return
        }

        val internalBufferSize = maxOf(minBufSize * 2, chunkSize * 4)

        // Try VOICE_RECOGNITION source first (includes hardware noise suppression / AGC), fallback to MIC
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

        try {
            record.startRecording()
        } catch (e: Exception) {
            Log.e(TAG, "startRecording failed: ${e.message}")
            record.release()
            callback?.onRecordingStateChanged(false, "startRecording exception")
            return
        }

        audioRecord = record
        isRecording.set(true)
        callback?.onRecordingStateChanged(true, "Recording: $sampleRate Hz ${if (channelCount == 2) "Stereo" else "Mono"}")

        // Background capture loop
        recordThread = Thread({
            Log.i(TAG, "🎙️ Mic capture loop started (session=$dataSessionId, chunkSize=$chunkSize)")
            val buffer = ByteArray(chunkSize)
            var totalBytesRead = 0L
            var frameCount = 0

            while (isRecording.get()) {
                val read = record.read(buffer, 0, chunkSize)
                if (read > 0) {
                    frameCount++
                    totalBytesRead += read
                    callback?.onAudioFrame(dataSessionId, buffer, 0, read)
                    if (frameCount <= 5 || frameCount % 100 == 0) {
                        Log.d(TAG, "🎙️ TX Mic frame #$frameCount ($read B, total=$totalBytesRead B)")
                    }
                } else if (read < 0) {
                    Log.w(TAG, "AudioRecord read returned error code: $read")
                    if (!isRecording.get()) break
                    try { Thread.sleep(10) } catch (_: InterruptedException) { break }
                }
            }
            Log.i(TAG, "🎙️ Mic capture loop stopped (total $frameCount frames, $totalBytesRead bytes)")
        }, "HiCar-MicRecordThread").apply {
            priority = Thread.MAX_PRIORITY
            start()
        }
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
        callback?.onRecordingStateChanged(false, "Stopped")
    }

    fun isRecording(): Boolean = isRecording.get()
}
