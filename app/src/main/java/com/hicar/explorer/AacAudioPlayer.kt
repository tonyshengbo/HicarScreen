package com.hicar.explorer

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Build
import android.util.Log
import com.hicar.explorer.media.AudioFocusManager
import java.nio.ByteBuffer

class AacAudioPlayer(context: Context? = null) {

    companion object {
        private const val TAG = "AacAudioPlayer"
        private const val SAMPLE_RATE = 48000
        private const val CHANNELS = 2
    }

    private val audioFocusManager: AudioFocusManager? = context?.let {
        AudioFocusManager(it, object : AudioFocusManager.FocusListener {
            override fun onGainFocus() {
                setVolume(1.0f)
            }

            override fun onLossFocus(isTransient: Boolean, canDuck: Boolean) {
                if (canDuck) {
                    setVolume(0.2f)
                } else {
                    setVolume(0.0f)
                }
            }
        })
    }

    private var audioTrack: AudioTrack? = null
    private var codec: MediaCodec? = null
    @Volatile
    private var isPlaying = false
    private var drainThread: Thread? = null

    private var frameCount = 0L
    private var byteCount = 0L

    private fun setVolume(vol: Float) {
        val track = audioTrack ?: return
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                track.setVolume(vol)
            } else {
                @Suppress("DEPRECATION")
                track.setStereoVolume(vol, vol)
            }
        } catch (_: Exception) {}
    }

    @Synchronized
    fun start() {
        if (isPlaying) return
        try {
            // 1. Initialize AudioTrack for stereo 48kHz 16-bit PCM
            val channelConfig = AudioFormat.CHANNEL_OUT_STEREO
            val encoding = AudioFormat.ENCODING_PCM_16BIT
            val minBufferSize = AudioTrack.getMinBufferSize(SAMPLE_RATE, channelConfig, encoding)
            val bufferSize = maxOf(minBufferSize * 4, 32768)

            audioTrack = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                AudioTrack.Builder()
                    .setAudioAttributes(
                        AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_MEDIA)
                            .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                            .build()
                    )
                    .setAudioFormat(
                        AudioFormat.Builder()
                            .setEncoding(encoding)
                            .setSampleRate(SAMPLE_RATE)
                            .setChannelMask(channelConfig)
                            .build()
                    )
                    .setBufferSizeInBytes(bufferSize)
                    .setTransferMode(AudioTrack.MODE_STREAM)
                    .build()
            } else {
                @Suppress("DEPRECATION")
                AudioTrack(
                    AudioManager.STREAM_MUSIC,
                    SAMPLE_RATE,
                    channelConfig,
                    encoding,
                    bufferSize,
                    AudioTrack.MODE_STREAM
                )
            }

            audioFocusManager?.requestFocus()
            audioTrack?.play()

            // 2. Initialize MediaCodec for AAC decoding with ADTS support
            val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_AAC, SAMPLE_RATE, CHANNELS).apply {
                setInteger(MediaFormat.KEY_IS_ADTS, 1)
                // csd-0 fallback for raw AAC-LC: 48000Hz, 2ch
                setByteBuffer("csd-0", ByteBuffer.wrap(byteArrayOf(0x11.toByte(), 0x90.toByte())))
            }
            val c = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_AAC)
            c.configure(format, null, null, 0)
            c.start()
            codec = c
            isPlaying = true

            // 3. Start PCM drain thread
            drainThread = Thread({ drainLoop() }, "AacAudioPlayer-Drain").apply {
                isDaemon = true
                priority = Thread.MAX_PRIORITY
                start()
            }
            Log.i(TAG, "🔊 AacAudioPlayer started successfully (48000Hz stereo, bufferSize=$bufferSize)")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start AacAudioPlayer: ${e.message}", e)
            stop()
        }
    }

    @Synchronized
    fun stop() {
        isPlaying = false
        audioFocusManager?.abandonFocus()
        try {
            drainThread?.interrupt()
            drainThread = null
        } catch (_: Exception) {}

        try {
            codec?.stop()
            codec?.release()
        } catch (_: Exception) {}
        codec = null

        try {
            audioTrack?.pause()
            audioTrack?.flush()
            audioTrack?.stop()
            audioTrack?.release()
        } catch (_: Exception) {}
        audioTrack = null

        Log.i(TAG, "🔇 AacAudioPlayer stopped")
    }

    /**
     * Plays a single AAC frame received over DMSDP.
     * Ensures an ADTS header is present (adding a 7-byte header if raw AAC).
     */
    fun playFrame(data: ByteArray, offset: Int, length: Int) {
        if (!isPlaying) {
            start()
        }
        if (length <= 0) return
        val c = codec ?: return

        try {
            val adtsPacket = ensureAdts(data, offset, length)
            val inIndex = c.dequeueInputBuffer(10_000L) // 10ms timeout
            if (inIndex >= 0) {
                val inBuffer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    c.getInputBuffer(inIndex)
                } else {
                    @Suppress("DEPRECATION")
                    c.inputBuffers[inIndex]
                } ?: return
                inBuffer.clear()
                inBuffer.put(adtsPacket)
                val ptsUs = frameCount * 1024L * 1_000_000L / SAMPLE_RATE
                c.queueInputBuffer(inIndex, 0, adtsPacket.size, ptsUs, 0)
                frameCount++
                byteCount += adtsPacket.size
                if (frameCount <= 5 || frameCount % 100 == 0L) {
                    val hexHead = adtsPacket.take(minOf(adtsPacket.size, 16)).joinToString("") { "%02x".format(it) }
                    Log.i(TAG, "RX Audio frame #$frameCount (${adtsPacket.size} B, total=${byteCount}B, head=$hexHead)")
                }
            } else {
                Log.w(TAG, "Audio input buffer timeout, dropping frame (inIndex=$inIndex)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error playing audio frame: ${e.message}")
        }
    }

    private fun drainLoop() {
        val info = MediaCodec.BufferInfo()
        val pcmChunk = ByteArray(8192)

        while (isPlaying) {
            try {
                val c = codec ?: break
                val outIndex = c.dequeueOutputBuffer(info, 10_000L)
                if (outIndex >= 0) {
                    val outBuffer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                        c.getOutputBuffer(outIndex)
                    } else {
                        @Suppress("DEPRECATION")
                        c.outputBuffers[outIndex]
                    }
                    if (outBuffer != null && info.size > 0) {
                        outBuffer.position(info.offset)
                        outBuffer.limit(info.offset + info.size)
                        var remaining = info.size
                        while (remaining > 0 && isPlaying) {
                            val toRead = minOf(remaining, pcmChunk.size)
                            outBuffer.get(pcmChunk, 0, toRead)
                            audioTrack?.write(pcmChunk, 0, toRead)
                            remaining -= toRead
                        }
                    }
                    c.releaseOutputBuffer(outIndex, false)
                } else if (outIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                    val newFormat = c.outputFormat
                    Log.i(TAG, "Audio output format changed: $newFormat")
                }
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isPlaying) {
                    Log.w(TAG, "Audio drainLoop exception: ${e.message}")
                }
            }
        }
    }

    private fun ensureAdts(data: ByteArray, offset: Int, length: Int): ByteArray {
        // If already ADTS (starts with 0xFFF syncword)
        if (length >= 2 && (data[offset].toInt() and 0xFF) == 0xFF && (data[offset + 1].toInt() and 0xF0) == 0xF0) {
            val out = ByteArray(length)
            System.arraycopy(data, offset, out, 0, length)
            return out
        }

        // Construct 7-byte ADTS header for AAC-LC stereo @ 48kHz
        val totalLen = length + 7
        val out = ByteArray(totalLen)
        val profile = 1 // AAC-LC (MPEG-4 Audio Object Type 2 - 1 = 1)
        val freqIdx = 3 // 48000 Hz
        val chanCfg = 2 // Stereo
        out[0] = 0xFF.toByte()
        out[1] = 0xF1.toByte() // MPEG-4, Layer 0, no CRC
        out[2] = (((profile and 0x3) shl 6) or ((freqIdx and 0xF) shl 2) or ((chanCfg shr 2) and 0x1)).toByte()
        out[3] = (((chanCfg and 0x3) shl 6) or ((totalLen shr 11) and 0x3)).toByte()
        out[4] = ((totalLen shr 3) and 0xFF).toByte()
        out[5] = (((totalLen and 0x7) shl 5) or 0x1F).toByte()
        out[6] = 0xFC.toByte()
        System.arraycopy(data, offset, out, 7, length)
        return out
    }
}
