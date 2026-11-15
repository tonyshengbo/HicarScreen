package com.hicar.explorer

import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Build
import android.util.Log
import android.view.Surface
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class H264RtpDecoder {

    companion object {
        private const val TAG = "H264RtpDecoder"
        private val START_CODE = byteArrayOf(0, 0, 0, 1)
    }

    private var surface: Surface? = null
    private var codec: MediaCodec? = null
    @Volatile
    private var isDecoding = false
    private var drainThread: Thread? = null

    private val fuBuffer = ByteArrayOutputStream(128 * 1024)
    private var fuInProgress = false

    private var packetCount = 0L
    private var frameCount = 0L
    private var nalCount = 0L

    @Volatile
    private var sessionKey: ByteArray? = null

    fun setSessionKey(key: ByteArray?) {
        this.sessionKey = if (key != null && key.size >= 16) key.copyOfRange(0, 16) else key
        val keyHex = this.sessionKey?.joinToString("") { "%02x".format(it) } ?: "null"
        Log.i(TAG, "🔑 Video decoder sessionKey set: $keyHex")
    }

    @Synchronized
    fun setSurface(newSurface: Surface?) {
        Log.i(TAG, "setSurface: $newSurface (valid=${newSurface?.isValid})")
        surface = newSurface
        stopDecoder()
        if (newSurface != null && newSurface.isValid) {
            startDecoder(newSurface)
        }
    }

    @Synchronized
    private fun startDecoder(surf: Surface) {
        try {
            val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, 1920, 1080)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                format.setInteger(MediaFormat.KEY_LOW_LATENCY, 1)
            }
            val c = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
            c.configure(format, surf, null, 0)
            c.start()
            codec = c
            isDecoding = true

            drainThread = Thread({ drainLoop() }, "H264RtpDecoder-Drain").apply {
                isDaemon = true
                start()
            }
            Log.i(TAG, "MediaCodec AVC decoder configured and running!")
        } catch (e: Exception) {
            Log.e(TAG, "Error configuring MediaCodec AVC decoder: ${e.message}", e)
            codec = null
            isDecoding = false
        }
    }

    @Synchronized
    fun stopDecoder() {
        isDecoding = false
        try {
            drainThread?.interrupt()
            drainThread = null
        } catch (_: Exception) {}

        try {
            codec?.stop()
            codec?.release()
        } catch (_: Exception) {}
        codec = null
        fuInProgress = false
        fuBuffer.reset()
        Log.i(TAG, "MediaCodec AVC decoder stopped")
    }

    private fun drainLoop() {
        val info = MediaCodec.BufferInfo()
        while (isDecoding) {
            try {
                val c = codec ?: break
                val outIndex = c.dequeueOutputBuffer(info, 10000)
                if (outIndex >= 0) {
                    c.releaseOutputBuffer(outIndex, true)
                    frameCount++
                    if (frameCount == 1L || frameCount <= 5L || frameCount % 60L == 0L) {
                        Log.i(TAG, "🖥️ Rendered video frame #$frameCount to SurfaceView!")
                    }
                } else if (outIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                    val newFormat = c.outputFormat
                    Log.i(TAG, "MediaCodec output format changed: $newFormat")
                }
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isDecoding) {
                    Log.w(TAG, "Exception in drainLoop: ${e.message}")
                }
                break
            }
        }
    }

    fun onRtpPacket(data: ByteArray, offset: Int, length: Int) {
        packetCount++
        if (length < 12) return

        val b0 = data[offset].toInt() and 0xFF
        val version = (b0 ushr 6) and 0x03
        if (version != 2) {
            if (length >= 4 && data[offset] == 0.toByte() && data[offset + 1] == 0.toByte() &&
                ((data[offset + 2] == 1.toByte()) || (data[offset + 2] == 0.toByte() && data[offset + 3] == 1.toByte()))) {
                feedNalDirect(data, offset, length)
            }
            return
        }

        val padding = ((b0 ushr 5) and 0x01) == 1
        val extension = ((b0 ushr 4) and 0x01) == 1
        val csrcCount = b0 and 0x0F

        var headerLen = 12 + (csrcCount * 4)
        if (offset + headerLen > offset + length) return

        if (extension && offset + headerLen + 4 <= offset + length) {
            val extProfile = ((data[offset + headerLen].toInt() and 0xFF) shl 8) or
                    (data[offset + headerLen + 1].toInt() and 0xFF)
            val extLenField = ((data[offset + headerLen + 2].toInt() and 0xFF) shl 8) or
                    (data[offset + headerLen + 3].toInt() and 0xFF)
            if (extProfile == 0x0001 && extLenField == 20) {
                // Huawei HiSight RTP extension header: 4 bytes (profile+len) + 20 bytes data = 24 bytes
                headerLen += 24
            } else {
                headerLen += 4 + (extLenField * 4)
            }
        }
        if (offset + headerLen > offset + length) return

        val padLen = if (padding && length > headerLen) data[offset + length - 1].toInt() and 0xFF else 0
        val payloadLen = length - headerLen - padLen
        if (payloadLen <= 0) return

        val payloadOffset = offset + headerLen

        if (packetCount <= 5 || packetCount % 300 == 0L) {
            val preview = data.copyOfRange(payloadOffset, minOf(payloadOffset + 32, offset + length))
                .joinToString("") { "%02x".format(it) }
            Log.i(TAG, "📦 RTP payload #$packetCount (hdrLen=$headerLen, payLen=$payloadLen): hex=$preview")
        }

        // Step 1: Check if payload is wrapped in MPEG PES (starts with 00 00 01)
        if (payloadLen >= 4 && data[payloadOffset] == 0.toByte() && data[payloadOffset + 1] == 0.toByte() && data[payloadOffset + 2] == 1.toByte()) {
            val streamId = data[payloadOffset + 3].toInt() and 0xFF
            if (streamId in 0xE0..0xEF || streamId == 0xBD) {
                // ES data starts at payloadOffset + 14 in Huawei HiSight PES format
                val esOffset = payloadOffset + 14
                val esLen = payloadLen - 14
                if (esLen > 0) {
                    val key = sessionKey
                    if (key != null && esLen >= 16) {
                        // Check if already plaintext (starts with 00 00 00 01 or 00 00 01)
                        val isPlain = (data[esOffset] == 0.toByte() && data[esOffset + 1] == 0.toByte() &&
                                (data[esOffset + 2] == 1.toByte() || (esLen >= 4 && data[esOffset + 2] == 0.toByte() && data[esOffset + 3] == 1.toByte())))
                        if (isPlain) {
                            feedNalDirect(data, esOffset, esLen)
                            return
                        }
                        // AES-128-CTR Decrypt: first 16 bytes is IV, remaining is ciphertext
                        try {
                            val iv = data.copyOfRange(esOffset, esOffset + 16)
                            val cipherBytes = data.copyOfRange(esOffset + 16, esOffset + esLen)
                            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
                            val plainEs = cipher.doFinal(cipherBytes)
                            if (packetCount <= 5 || packetCount % 300 == 0L) {
                                val plainHex = plainEs.take(minOf(plainEs.size, 16)).joinToString("") { "%02x".format(it) }
                                Log.i(TAG, "🔓 Decrypted ES frame #$packetCount (${plainEs.size} B): hex=$plainHex")
                            }
                            feedNalDirect(plainEs, 0, plainEs.size)
                            return
                        } catch (e: Exception) {
                            Log.w(TAG, "Error decrypting ES frame #$packetCount: ${e.message}")
                        }
                    }
                    feedNalDirect(data, esOffset, esLen)
                    return
                }
            }
        }

        // Step 2: Check if payload is already Annex B (starts with 00 00 00 01 or 00 00 01)
        if (payloadLen >= 4 && data[payloadOffset] == 0.toByte() && data[payloadOffset + 1] == 0.toByte()) {
            if (data[payloadOffset + 2] == 1.toByte() || (data[payloadOffset + 2] == 0.toByte() && data[payloadOffset + 3] == 1.toByte())) {
                feedNalDirect(data, payloadOffset, payloadLen)
                return
            }
        }

        // Step 3: Standard RFC 6184 NAL encapsulation
        val nalHeader = data[payloadOffset].toInt() and 0xFF
        val nalType = nalHeader and 0x1F

        when (nalType) {
            in 1..23 -> {
                // Single NAL unit packet
                feedNalWithStartCode(data, payloadOffset, payloadLen)
            }
            24 -> {
                // STAP-A aggregation packet
                var p = payloadOffset + 1
                val end = payloadOffset + payloadLen
                while (p + 2 <= end) {
                    val unitSize = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
                    p += 2
                    if (p + unitSize > end) break
                    feedNalWithStartCode(data, p, unitSize)
                    p += unitSize
                }
            }
            28 -> {
                // FU-A fragmentation unit
                if (payloadLen < 2) return
                val fuIndicator = nalHeader
                val fuHeader = data[payloadOffset + 1].toInt() and 0xFF
                val isStart = (fuHeader and 0x80) != 0
                val isEnd = (fuHeader and 0x40) != 0
                val origNalType = fuHeader and 0x1F
                val reconstructedHeader = (fuIndicator and 0xE0) or origNalType

                if (isStart) {
                    fuBuffer.reset()
                    fuBuffer.write(START_CODE)
                    fuBuffer.write(reconstructedHeader)
                    fuBuffer.write(data, payloadOffset + 2, payloadLen - 2)
                    fuInProgress = true
                } else if (fuInProgress) {
                    fuBuffer.write(data, payloadOffset + 2, payloadLen - 2)
                    if (isEnd) {
                        val nalBytes = fuBuffer.toByteArray()
                        feedNalDirect(nalBytes, 0, nalBytes.size)
                        fuInProgress = false
                        fuBuffer.reset()
                    }
                }
            }
            else -> {
                if (packetCount <= 10 || packetCount % 300 == 0L) {
                    Log.w(TAG, "Unrecognized RTP payload format: b0=0x${"%02x".format(nalHeader)} (len=$payloadLen)")
                }
            }
        }
    }

    fun feedRawH264(data: ByteArray, offset: Int, length: Int) {
        feedNalDirect(data, offset, length)
    }

    private fun feedNalWithStartCode(data: ByteArray, offset: Int, length: Int) {
        val totalLen = 4 + length
        val buf = ByteArray(totalLen)
        buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 1
        System.arraycopy(data, offset, buf, 4, length)
        feedNalDirect(buf, 0, totalLen)
    }

    private fun feedNalDirect(data: ByteArray, offset: Int, length: Int) {
        var c = codec
        if (c == null || !isDecoding) {
            surface?.let { surf ->
                if (surf.isValid) {
                    Log.i(TAG, "Decoder not running on NAL arrival, restarting with valid surface...")
                    startDecoder(surf)
                    c = codec
                }
            }
        }
        val activeCodec = c ?: return
        if (!isDecoding) return

        nalCount++
        try {
            val inIndex = activeCodec.dequeueInputBuffer(10000)
            if (inIndex >= 0) {
                val inBuf = activeCodec.getInputBuffer(inIndex)
                if (inBuf != null) {
                    inBuf.clear()
                    inBuf.put(data, offset, length)
                    val ptsUs = System.nanoTime() / 1000L
                    activeCodec.queueInputBuffer(inIndex, 0, length, ptsUs, 0)
                    if (nalCount <= 5 || nalCount % 100 == 0L) {
                        val preview = data.copyOfRange(offset, minOf(offset + 16, offset + length))
                            .joinToString("") { "%02x".format(it) }
                        Log.i(TAG, "📥 Queued NAL #$nalCount into codec ($length B, pts=$ptsUs): hex=$preview")
                    }
                }
            } else {
                if (nalCount % 100 == 0L) {
                    Log.w(TAG, "Codec input buffer busy, dropped NAL #$nalCount (len=$length)")
                }
            }
        } catch (e: Exception) {
            if (isDecoding) {
                Log.w(TAG, "Error queuing NAL into codec: ${e.message}")
            }
        }
    }
}
