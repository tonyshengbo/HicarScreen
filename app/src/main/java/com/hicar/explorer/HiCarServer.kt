package com.hicar.explorer

import android.content.Context
import android.media.MediaCodec
import android.media.MediaFormat
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.util.Log
import android.view.Surface
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * HiCarServer – Registers mDNS service (_hicar._tcp) and runs a TCP capture server.
 *
 * The Huawei phone's HiCar app will:
 *   1. Discover "_hicar._tcp" via mDNS / Bonjour on the local Wi-Fi Direct network
 *   2. Connect to our TCP port 8899
 *   3. Send its protocol handshake / data
 *
 * We capture ALL raw bytes and report them via the Callback for display & analysis.
 */
class HiCarServer(
    private val context: Context,
    private val btServer: HiCarBtServer,
    private val callback: Callback
) {

    interface Callback {
        fun onMdnsStatusChanged(registered: Boolean, detail: String)
        fun onTcpStatusChanged(running: Boolean, detail: String)
        fun onDataReceived(clientInfo: String, data: ByteArray)
    }

    companion object {
        private const val TAG = "HiCarServer"
        const val SERVICE_TYPE = "_hicar._tcp."
        const val SERVICE_NAME = "HiCarReceiver"
        const val TCP_PORT = 8899
        const val TCP_PORT_ALT = 7899   // some HiCar versions use this
        const val DMSDP_PORT = 9999     // DMSDP RTSP control port
    }

    private val nsdManager: NsdManager =
        context.getSystemService(Context.NSD_SERVICE) as NsdManager

    private var serverSocket: ServerSocket? = null
    private var altServerSocket: ServerSocket? = null
    private var dmsdpServerSocket: ServerSocket? = null
    private var udpSocket: java.net.DatagramSocket? = null
    private var videoTcpSocket: java.net.Socket? = null
    private var controlTcpSocket: java.net.Socket? = null
    private val controlLock = Any()
    private val touchRandom = java.security.SecureRandom()
    private val videoDecoder = H264RtpDecoder()
    private val audioPlayer = AacAudioPlayer()
    private val running = AtomicBoolean(false)
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private var registrationListener: NsdManager.RegistrationListener? = null

    // ─── Public API ───────────────────────────────────────────────────────────

    fun setSurface(surface: android.view.Surface?) {
        videoDecoder.setSurface(surface)
    }

    fun start() {
        if (running.getAndSet(true)) return
        audioPlayer.start()
        startTcpServer(TCP_PORT)
        startTcpServer(TCP_PORT_ALT)
        startTcpServer(DMSDP_PORT)
        registerMdns()
    }

    fun stop() {
        running.set(false)
        videoDecoder.stopDecoder()
        audioPlayer.stop()
        unregisterMdns()
        try { serverSocket?.close() } catch (_: IOException) {}
        try { altServerSocket?.close() } catch (_: IOException) {}
        try { dmsdpServerSocket?.close() } catch (_: IOException) {}
        try { udpSocket?.close() } catch (_: IOException) {}
        try { videoTcpSocket?.close() } catch (_: IOException) {}
        try { controlTcpSocket?.close() } catch (_: IOException) {}
        serverSocket = null
        altServerSocket = null
        dmsdpServerSocket = null
        udpSocket = null
        videoTcpSocket = null
        controlTcpSocket = null
        callback.onTcpStatusChanged(false, "Server stopped")
        callback.onMdnsStatusChanged(false, "mDNS unregistered")
    }

    // ─── TCP ──────────────────────────────────────────────────────────────────

    private fun startTcpServer(port: Int) {
        executor.submit {
            try {
                val ss = ServerSocket(port)
                if (port == TCP_PORT) {
                    serverSocket = ss
                    callback.onTcpStatusChanged(true, "Listening on port $port")
                } else if (port == DMSDP_PORT) {
                    dmsdpServerSocket = ss
                    Log.i(TAG, "DMSDP TCP server on port $port")
                } else {
                    altServerSocket = ss
                    Log.i(TAG, "Alt TCP server on port $port")
                }
                Log.i(TAG, "TCP server started on port $port")

                while (running.get() && !ss.isClosed) {
                    try {
                        val client = ss.accept()
                        handleClient(client, port)
                    } catch (e: IOException) {
                        if (running.get()) Log.e(TAG, "Accept error on port $port: ${e.message}")
                        break
                    }
                }
            } catch (e: IOException) {
                val msg = "Port $port failed: ${e.message}"
                Log.e(TAG, msg)
                if (port == TCP_PORT) callback.onTcpStatusChanged(false, msg)
            }
        }
    }

    private fun handleClient(socket: Socket, port: Int) {
        executor.submit {
            val clientInfo = "${socket.inetAddress.hostAddress}:${socket.port} -> :$port"
            callback.onTcpStatusChanged(true, "Client connected: $clientInfo")
            Log.i(TAG, "Client connected: $clientInfo")

            if (port == DMSDP_PORT) {
                handleDmsdpClient(socket, clientInfo)
                return@submit
            }

            try {
                btServer.handleStream(
                    socket.getInputStream(),
                    socket.getOutputStream(),
                    "TCP:$clientInfo",
                    onData = { data -> callback.onDataReceived(clientInfo, data) }
                ) {
                    try { socket.close() } catch (_: Exception) {}
                    callback.onTcpStatusChanged(true, "Client disconnected: $clientInfo | Waiting...")
                }
            } catch (e: Exception) {
                Log.w(TAG, "Client $clientInfo error: ${e.message}")
                try { socket.close() } catch (_: Exception) {}
                callback.onTcpStatusChanged(true, "Client error: ${e.message} | Waiting...")
            }
        }
    }

    private fun handleDmsdpClient(socket: Socket, clientInfo: String) {
        Log.i(TAG, "DMSDP Client connected from $clientInfo")
        callback.onTcpStatusChanged(true, "DMSDP Client connected: $clientInfo")
        val inStream = socket.getInputStream()
        val out = socket.getOutputStream()

        // AES-128-CTR Cipher instances for this session
        var aesEnc: Cipher? = null
        var aesDec: Cipher? = null
        var isCryptoActive = false

        fun decryptDmsdp(body: ByteArray): ByteArray {
            val key = btServer.getSessionKey() ?: run {
                Log.w(TAG, "decryptDmsdp: session key is null!")
                return body
            }
            if (body.size < 16) return body
            val iv = body.copyOfRange(0, 16)
            val cipherBytes = body.copyOfRange(16, body.size)
            return try {
                val keySpec = SecretKeySpec(key.copyOfRange(0, 16), "AES")
                val ivSpec = IvParameterSpec(iv)
                val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
                val plain = cipher.doFinal(cipherBytes)
                Log.i(TAG, "decryptDmsdp SUCCESS: ${cipherBytes.size}B cipher -> ${plain.size}B plain (IV=${iv.joinToString("") { "%02x".format(it) }})")
                plain
            } catch (e: Exception) {
                Log.e(TAG, "DMSDP decrypt failed: ${e.message}")
                body
            }
        }

        fun encryptDmsdp(plainBytes: ByteArray): ByteArray {
            val key = btServer.getSessionKey() ?: return plainBytes
            val iv = ByteArray(16).apply { java.security.SecureRandom().nextBytes(this) }
            return try {
                val keySpec = SecretKeySpec(key.copyOfRange(0, 16), "AES")
                val ivSpec = IvParameterSpec(iv)
                val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
                val cipherBytes = cipher.doFinal(plainBytes)
                val result = ByteArray(16 + cipherBytes.size)
                System.arraycopy(iv, 0, result, 0, 16)
                System.arraycopy(cipherBytes, 0, result, 16, cipherBytes.size)
                result
            } catch (e: Exception) {
                Log.e(TAG, "DMSDP encrypt failed: ${e.message}")
                plainBytes
            }
        }

        // Helper to send a framed DMSDP message (magic 0x00 for plaintext, 0xAB for encrypted)
        fun sendDmsdp(payload: String, forcePlain: Boolean = false) {
            val plainBytes = payload.toByteArray(StandardCharsets.UTF_8)
            val useCrypto = !forcePlain && isCryptoActive && btServer.getSessionKey() != null
            val magic = if (useCrypto) 0xAB.toByte() else 0x00.toByte()
            val body = if (useCrypto) encryptDmsdp(plainBytes) else plainBytes
            val len = body.size
            val frame = ByteArray(3 + len)
            frame[0] = magic
            frame[1] = ((len shr 8) and 0xFF).toByte()
            frame[2] = (len and 0xFF).toByte()
            System.arraycopy(body, 0, frame, 3, len)
            out.write(frame)
            out.flush()
            Log.i(TAG, "TX DMSDP frame (magic=0x%02X, len=$len B) to $clientInfo:\n$payload".format(magic))
            callback.onDataReceived(clientInfo, frame)
        }

        fun sendDmsdpBinary(module: Int, type: Int, payload: ByteArray) {
            val frameLen = 11 + payload.size
            val binFrame = ByteArray(frameLen)
            binFrame[0] = 0x24.toByte() // '$'
            binFrame[1] = ((module shr 24) and 0xFF).toByte()
            binFrame[2] = ((module shr 16) and 0xFF).toByte()
            binFrame[3] = ((module shr 8) and 0xFF).toByte()
            binFrame[4] = (module and 0xFF).toByte()
            binFrame[5] = ((type shr 24) and 0xFF).toByte()
            binFrame[6] = ((type shr 16) and 0xFF).toByte()
            binFrame[7] = ((type shr 8) and 0xFF).toByte()
            binFrame[8] = (type and 0xFF).toByte()
            binFrame[9] = ((payload.size shr 8) and 0xFF).toByte()
            binFrame[10] = (payload.size and 0xFF).toByte()
            System.arraycopy(payload, 0, binFrame, 11, payload.size)

            val useCrypto = isCryptoActive && btServer.getSessionKey() != null
            val magic = if (useCrypto) 0xAB.toByte() else 0x00.toByte()
            val body = if (useCrypto) encryptDmsdp(binFrame) else binFrame
            val len = body.size
            val frame = ByteArray(3 + len)
            frame[0] = magic
            frame[1] = ((len shr 8) and 0xFF).toByte()
            frame[2] = (len and 0xFF).toByte()
            System.arraycopy(body, 0, frame, 3, len)
            out.write(frame)
            out.flush()
            Log.i(TAG, "TX DMSDP Binary frame (module=$module, type=$type, payloadLen=${payload.size}, totalLen=$len)")
        }

        // Helper to read a raw framed DMSDP payload
        fun readDmsdpRaw(): ByteArray? {
            val header = ByteArray(3)
            var hRead = 0
            while (hRead < 3) {
                val r = inStream.read(header, hRead, 3 - hRead)
                if (r < 0) return null
                hRead += r
            }
            val magic = header[0].toInt() and 0xFF
            val len = ((header[1].toInt() and 0xFF) shl 8) or (header[2].toInt() and 0xFF)

            if (magic != 0x00 && magic != 0xAB) {
                Log.w(TAG, "RX unexpected DMSDP magic: 0x%02X len=$len, attempting resync".format(magic))
                while (true) {
                    val b = inStream.read()
                    if (b < 0) return null
                    if (b == 0x00 || b == 0xAB) {
                        val lenBytes = ByteArray(2)
                        var lRead = 0
                        while (lRead < 2) {
                            val lr = inStream.read(lenBytes, lRead, 2 - lRead)
                            if (lr < 0) return null
                            lRead += lr
                        }
                        val resyncLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
                        val p = ByteArray(resyncLen)
                        var pRead = 0
                        while (pRead < resyncLen) {
                            val pr = inStream.read(p, pRead, resyncLen - pRead)
                            if (pr < 0) return null
                            pRead += pr
                        }
                        return if (b == 0xAB) {
                            isCryptoActive = true
                            decryptDmsdp(p)
                        } else {
                            p
                        }
                    }
                }
            }

            val body = ByteArray(len)
            var bRead = 0
            while (bRead < len) {
                val r = inStream.read(body, bRead, len - bRead)
                if (r < 0) return null
                bRead += r
            }

            return if (magic == 0xAB) {
                isCryptoActive = true
                decryptDmsdp(body)
            } else {
                body
            }
        }

        fun encodeVarInt(value: Int): ByteArray {
            var v = value
            val buf = mutableListOf<Byte>()
            while (true) {
                val b = (v and 0x7F).toByte()
                v = v ushr 7
                if (v == 0) {
                    buf.add((b.toInt() or 0x80).toByte())
                    break
                } else {
                    buf.add(b)
                }
            }
            return buf.toByteArray()
        }

        fun decodeVarInt(data: ByteArray, offset: Int = 0): Pair<Int, Int> {
            var value = 0
            var shift = 0
            var cur = offset
            while (cur < data.size) {
                val b = data[cur].toInt() and 0xFF
                value = value or ((b and 0x7F) shl shift)
                cur++
                if ((b and 0x80) != 0) break
                shift += 7
            }
            return Pair(value, cur)
        }

        fun sendCarDeviceInfo() {
            Log.i(TAG, "Sending Car Device Info (cmd 101)...")
            val carDevice = org.json.JSONObject().apply {
                put("deviceId", "2C4A217A912239")
                put("deviceName", "极氪001")
                put("deviceType", 4)
                put("bluetoothMac", "82:FA:DF:77:1B:F8")
                put("btName", "极氪001")
                put("localIp", "192.168.49.1")
                put("remoteIp", "192.168.49.2")
                put("port", 9999)
                put("businessId", 1)
                put("properties", org.json.JSONObject())
            }.toString().toByteArray(StandardCharsets.UTF_8)
            val devPayload = ByteArray(1 + carDevice.size).apply {
                this[0] = 0xE5.toByte() // cmd 101
                System.arraycopy(carDevice, 0, this, 1, carDevice.size)
            }
            sendDmsdpBinary(3, -1, devPayload)
        }

        fun sendServices() {
            Log.i(TAG, "Sending HiCar DMSDP services (Display, Audio, Mic)...")
            // 1. Send Display Service (serviceType = 8, cmd 102)
            val dispJson = org.json.JSONObject().apply {
                put("deviceId", "2C4A217A912239")
                put("deviceName", "极氪001")
                put("serviceId", "service_display_1")
                put("serviceType", 8)
                put("status", org.json.JSONObject())
                put("properties", org.json.JSONObject().apply {
                    put("1005", 1920)
                    put("1006", 1080)
                    put("1009", 1920)
                    put("1010", 1080)
                    put("1015", 160)
                    put("1016", 1920)
                    put("1017", 1080)
                    put("1018", 1)
                    put("1019", 60)
                    put("1021", 10000000)
                    put("5004", true)
                })
            }.toString().toByteArray(StandardCharsets.UTF_8)
            val dispPayload = ByteArray(1 + dispJson.size).apply {
                this[0] = 0xE6.toByte() // cmd 102
                System.arraycopy(dispJson, 0, this, 1, dispJson.size)
            }
            sendDmsdpBinary(3, 0, dispPayload)

            // 2. Send Speaker Service (serviceType = 4, cmd 102)
            val spkJson = org.json.JSONObject().apply {
                put("deviceId", "2C4A217A912239")
                put("deviceName", "极氪001")
                put("serviceId", "service_audio_1")
                put("serviceType", 4)
                put("status", org.json.JSONObject())
                put("properties", org.json.JSONObject())
            }.toString().toByteArray(StandardCharsets.UTF_8)
            val spkPayload = ByteArray(1 + spkJson.size).apply {
                this[0] = 0xE6.toByte() // cmd 102
                System.arraycopy(spkJson, 0, this, 1, spkJson.size)
            }
            sendDmsdpBinary(3, 0, spkPayload)

            // 3. Send Mic Service (serviceType = 2, cmd 102)
            val micJson = org.json.JSONObject().apply {
                put("deviceId", "2C4A217A912239")
                put("deviceName", "极氪001")
                put("serviceId", "service_mic_1")
                put("serviceType", 2)
                put("status", org.json.JSONObject())
                put("properties", org.json.JSONObject())
            }.toString().toByteArray(StandardCharsets.UTF_8)
            val micPayload = ByteArray(1 + micJson.size).apply {
                this[0] = 0xE6.toByte() // cmd 102
                System.arraycopy(micJson, 0, this, 1, micJson.size)
            }
            sendDmsdpBinary(3, 0, micPayload)

            // 4. Send HiSight Video Display Port 50000 on Module 5
            val portBytes = encodeVarInt(50000)
            val mod5Payload = ByteArray(1 + portBytes.size).apply {
                this[0] = 0xE5.toByte() // cmd 101
                System.arraycopy(portBytes, 0, this, 1, portBytes.size)
            }
            sendDmsdpBinary(5, -1, mod5Payload)
            Log.i(TAG, "Sent Module 5 Display port 50000 (${mod5Payload.joinToString("") { "%02x".format(it) }})")
        }

        fun handleBinaryControl(raw: ByteArray) {
            if (raw.size < 11) return
            val module = ((raw[1].toInt() and 0xFF) shl 24) or ((raw[2].toInt() and 0xFF) shl 16) or ((raw[3].toInt() and 0xFF) shl 8) or (raw[4].toInt() and 0xFF)
            val type = ((raw[5].toInt() and 0xFF) shl 24) or ((raw[6].toInt() and 0xFF) shl 16) or ((raw[7].toInt() and 0xFF) shl 8) or (raw[8].toInt() and 0xFF)
            val pLen = ((raw[9].toInt() and 0xFF) shl 8) or (raw[10].toInt() and 0xFF)
            if (raw.size < 11 + pLen) return

            // Audio stream packet: type == -19088893 (0xFEDCBA03) or lower byte == 3 (Audio service type)
            if (type == -19088893 || (type and 0xFF) == 3) {
                val innerHeaderLen = 18
                if (pLen > innerHeaderLen) {
                    val aacOffset = 11 + innerHeaderLen
                    val aacLen = pLen - innerHeaderLen
                    audioPlayer.playFrame(raw, aacOffset, aacLen)
                }
                return
            }

            val (cmd, cmdOffset) = decodeVarInt(raw, 11)
            val payloadLen = (11 + pLen) - cmdOffset
            val jsonStr = if (payloadLen > 0) String(raw, cmdOffset, payloadLen, StandardCharsets.UTF_8) else ""
            Log.i(TAG, "RX DMSDP Binary: module=$module, type=$type, cmd=$cmd, payloadLen=$payloadLen, payload: $jsonStr")

            // Module 3: Device & Service Management
            if (module == 3) {
                // If phone sent device info (cmd == 101 / 0xE5)
                if (cmd == 101) {
                    sendCarDeviceInfo()
                    sendServices()
                } else if (cmd == 104) {
                    // Phone is requesting services (cmd 104 REQ_SERVICE_INFO)
                    Log.i(TAG, "Phone requested service info (cmd 104)! Replying with all services...")
                    sendServices()
                }
            } else if (module == 5) {
                // Module 5: Display port exchange
                Log.i(TAG, "RX Module 5 display message (cmd=$cmd, len=$payloadLen).")
                if (cmd == 101 && payloadLen >= 1) {
                    val (phoneRtspPort, _) = decodeVarInt(raw, cmdOffset)
                    Log.i(TAG, ">>> RX Phone HiSight RTSP Server Port: $phoneRtspPort! Launching HiSight RTSP Client...")
                    startHiSightRtspClient("192.168.49.2", phoneRtspPort)
                }
                val portBytes = encodeVarInt(50000)
                val mod5Payload = ByteArray(1 + portBytes.size).apply {
                    this[0] = 0xE5.toByte() // cmd 101
                    System.arraycopy(portBytes, 0, this, 1, portBytes.size)
                }
                sendDmsdpBinary(5, -1, mod5Payload)
            }
        }

        // Start UDP receiver in advance so we never drop early RTP packets
        startUdpReceiver(50000)

        // Active CSeq counter for car-initiated requests (OPTIONS, GET_PARAMETER keepalive)
        val carCSeq = java.util.concurrent.atomic.AtomicInteger(1)

        // Step 1: Send OPTIONS request with magic=0x00 (plaintext) and CryptoAbility=222
        try {
            val optionsReq = "OPTIONS * DMSDP/1.0\r\n" +
                    "CSeq: ${carCSeq.getAndIncrement()}\r\n" +
                    "CryptoVer: 1\r\n" +
                    "CryptoAbility: 222\r\n" +
                    "CryptoAlg: aes128-ctr\r\n" +
                    "UnpackAssembly: 90\r\n" +
                    "CompressFlag: 165\r\n" +
                    "UdpKA: 0\r\n" +
                    "KaRetry: 10\r\n" +
                    "LowDelay: 1\r\n\r\n"
            sendDmsdp(optionsReq, forcePlain = true)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send DMSDP OPTIONS: ${e.message}")
            try { socket.close() } catch (_: Exception) {}
            return
        }

        // Active KeepAlive Timer: Huawei phone requires GET_PARAMETER probes from car to set alive=1
        val keepAliveScheduler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()
        keepAliveScheduler.scheduleWithFixedDelay({
            if (running.get() && !socket.isClosed) {
                try {
                    val kaCSeq = carCSeq.getAndIncrement()
                    val kaReq = "GET_PARAMETER * DMSDP/1.0\r\n" +
                            "CSeq: $kaCSeq\r\n\r\n"
                    sendDmsdp(kaReq)
                    Log.i(TAG, "TX Active KeepAlive probe to Phone: CSeq $kaCSeq")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to send active keepalive: ${e.message}")
                }
            }
        }, 1000, 1000, java.util.concurrent.TimeUnit.MILLISECONDS)

        // Helper to echo back required routing headers to satisfy phone's CSeq & service lookup
        fun buildContextHeaders(headers: Map<String, String>): String {
            val sb = java.lang.StringBuilder()
            headers["serviceid"]?.let { sb.append("ServiceID: ").append(it).append("\r\n") }
            headers["servicetype"]?.let { sb.append("ServiceType: ").append(it).append("\r\n") }
            headers["datasessionid"]?.let { sb.append("DataSessionID: ").append(it).append("\r\n") }
            headers["session"]?.let { sb.append("Session: ").append(it).append("\r\n") }
            return sb.toString()
        }

        // Step 2: Loop reading framed DMSDP messages
        try {
            while (running.get() && !socket.isClosed) {
                val rawMessage = readDmsdpRaw() ?: break
                if (rawMessage.isNotEmpty() && rawMessage[0] == 0x24.toByte()) {
                    handleBinaryControl(rawMessage)
                    continue
                }
                val message = String(rawMessage, StandardCharsets.UTF_8)
                Log.i(TAG, "RX DMSDP frame (${message.length} chars):\n$message")
                callback.onDataReceived(clientInfo, rawMessage)

                val lines = message.split("\r\n", "\n")
                if (lines.isEmpty()) continue
                val requestLine = lines[0].trim()
                if (requestLine.isEmpty()) continue

                val headers = mutableMapOf<String, String>()
                for (i in 1 until lines.size) {
                    val line = lines[i].trim()
                    if (line.isEmpty()) break // end of headers
                    val colon = line.indexOf(':')
                    if (colon > 0) {
                        val k = line.substring(0, colon).trim().lowercase()
                        val v = line.substring(colon + 1).trim()
                        headers[k] = v
                    }
                }

                val cseq = headers["cseq"] ?: "1"
                val ctxHeaders = buildContextHeaders(headers)
                val parts = requestLine.split(" ")
                val method = parts[0].uppercase()

                when (method) {
                    "SET_PARAMETER" -> {
                        val resp = "DMSDP/1.0 200 OK\r\n" +
                                ctxHeaders +
                                "CSeq: $cseq\r\n\r\n"
                        sendDmsdp(resp)
                        if (!isCryptoActive) {
                            isCryptoActive = true
                            Log.i(TAG, "DMSDP crypto activated! Proactively registering car device & services...")
                            executor.submit {
                                try {
                                    Thread.sleep(100)
                                    sendCarDeviceInfo()
                                    Thread.sleep(50)
                                    sendServices()
                                } catch (e: Exception) {
                                    Log.e(TAG, "Error in proactive service registration: ${e.message}")
                                }
                            }
                        }

                        // Handle msdp_trigger_method (e.g. OPTIONS, SETUP, TEARDOWN)
                        val triggerMethod = if (message.contains("msdp_trigger_method:")) {
                            message.substringAfter("msdp_trigger_method:").substringBefore("\r\n").substringBefore("\n").trim()
                        } else headers["msdp_trigger_method"]

                        if (triggerMethod != null && triggerMethod.equals("OPTIONS", ignoreCase = true)) {
                            val serviceId = headers["serviceid"] ?: "service_audio_1"
                            val serviceType = headers["servicetype"] ?: "3"
                            val optCSeq = carCSeq.getAndIncrement()
                            Log.i(TAG, "Phone triggered DMSDP OPTIONS for $serviceId! Sending OPTIONS request (CSeq $optCSeq)...")
                            val optReq = "OPTIONS * DMSDP/1.0\r\n" +
                                    "ServiceID: $serviceId\r\n" +
                                    "ServiceType: $serviceType\r\n" +
                                    "CSeq: $optCSeq\r\n\r\n"
                            sendDmsdp(optReq)
                        }
                    }
                    "SETUP" -> {
                        val transport = headers["transport"] ?: ""
                        val clientPortMatch = Regex("client_port=(\\d+-\\d+)").find(transport)
                        val clientPort = clientPortMatch?.groupValues?.get(1) ?: "50000-50001"
                        val sessionVal = headers["session"] ?: "12345678"
                        val resp = "DMSDP/1.0 200 OK\r\n" +
                                ctxHeaders +
                                "CSeq: $cseq\r\n" +
                                "Session: $sessionVal\r\n" +
                                "Transport: RTP/AVP/UDP;unicast;client_port=$clientPort;server_port=50000-50001\r\n\r\n"
                        sendDmsdp(resp)
                        startUdpReceiver(50000)
                    }
                    "PLAY" -> {
                        val sessionVal = headers["session"] ?: "12345678"
                        val resp = "DMSDP/1.0 200 OK\r\n" +
                                ctxHeaders +
                                "CSeq: $cseq\r\n" +
                                "Session: $sessionVal\r\n" +
                                "Range: npt=0.000-\r\n\r\n"
                        sendDmsdp(resp)
                    }
                    "GET_PARAMETER" -> {
                        if (requestLine.contains("*")) {
                            Log.i(TAG, "RX one-way KeepAlive GET_PARAMETER * probe from phone, not replying 200 OK to avoid unsolicited response error")
                        } else {
                            val resp = "DMSDP/1.0 200 OK\r\n" +
                                    ctxHeaders +
                                    "CSeq: $cseq\r\n\r\n"
                            sendDmsdp(resp)
                        }
                    }
                    "OPTIONS" -> {
                        val resp = "DMSDP/1.0 200 OK\r\n" +
                                ctxHeaders +
                                "CSeq: $cseq\r\n" +
                                "Public: OPTIONS, SET_PARAMETER, SETUP, PLAY, GET_PARAMETER, TEARDOWN\r\n\r\n"
                        sendDmsdp(resp)
                    }
                    "TEARDOWN" -> {
                        val resp = "DMSDP/1.0 200 OK\r\n" +
                                ctxHeaders +
                                "CSeq: $cseq\r\n\r\n"
                        sendDmsdp(resp)
                        break
                    }
                    else -> {
                        if (requestLine.startsWith("DMSDP/")) {
                            Log.i(TAG, "RX DMSDP response from phone: $requestLine (CSeq: $cseq)")
                            if (btServer.getSessionKey() != null) {
                                isCryptoActive = true
                                Log.i(TAG, "DMSDP activated crypto mode for subsequent frames")
                            }
                        } else {
                            Log.w(TAG, "RX unknown DMSDP method: $method")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "DMSDP client $clientInfo error: ${e.message}")
        } finally {
            keepAliveScheduler.shutdownNow()
            try { socket.close() } catch (_: Exception) {}
            callback.onTcpStatusChanged(true, "DMSDP Client disconnected: $clientInfo | Waiting...")
        }
    }

    private fun startHiSightRtspClient(phoneIp: String, port: Int) {
        executor.submit {
            Log.i(TAG, "=== HiSight RTSP Client connecting to $phoneIp:$port ===")
            var rtspSocket: java.net.Socket? = null
            try {
                var connected = false
                for (retry in 1..10) {
                    try {
                        val s = java.net.Socket()
                        s.connect(java.net.InetSocketAddress(phoneIp, port), 2000)
                        s.tcpNoDelay = true
                        rtspSocket = s
                        connected = true
                        Log.i(TAG, "HiSight RTSP TCP Connected to $phoneIp:$port on attempt $retry!")
                        break
                    } catch (e: Exception) {
                        Log.w(TAG, "HiSight RTSP connect attempt $retry failed: ${e.message}, retrying in 200ms...")
                        Thread.sleep(200)
                    }
                }
                if (!connected || rtspSocket == null) {
                    Log.e(TAG, "Failed to connect to HiSight RTSP server at $phoneIp:$port after retries")
                    return@submit
                }

                val socket = rtspSocket
                val inStream = socket.getInputStream()
                val outStream = socket.getOutputStream()

                val sessionKey = btServer.getSessionKey()
                if (sessionKey == null) {
                    Log.e(TAG, "HiSight RTSP: sessionKey is null!")
                    return@submit
                }
                val keySpec = SecretKeySpec(sessionKey.copyOfRange(0, 16), "AES")
                val secureRandom = java.security.SecureRandom()
                var rtspEncrypted = false

                fun encryptPayload(plainBytes: ByteArray): ByteArray {
                    val iv = ByteArray(16).apply { secureRandom.nextBytes(this) }
                    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(iv))
                    val cipherBytes = cipher.doFinal(plainBytes)
                    val result = ByteArray(16 + cipherBytes.size)
                    System.arraycopy(iv, 0, result, 0, 16)
                    System.arraycopy(cipherBytes, 0, result, 16, cipherBytes.size)
                    return result
                }

                fun decryptPayload(cipherFrame: ByteArray): ByteArray {
                    if (cipherFrame.size < 16) return cipherFrame
                    val iv = cipherFrame.copyOfRange(0, 16)
                    val cipherBytes = cipherFrame.copyOfRange(16, cipherFrame.size)
                    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
                    return cipher.doFinal(cipherBytes)
                }

                fun sendFramedRtsp(msg: String, encrypt: Boolean = rtspEncrypted) {
                    Log.i(TAG, "TX HiSight RTSP (enc=$encrypt, len=${msg.length}):\n$msg")
                    val plainBytes = msg.toByteArray(StandardCharsets.UTF_8)
                    val payload = if (encrypt) encryptPayload(plainBytes) else plainBytes
                    val len = payload.size
                    val header = byteArrayOf(
                        ((len ushr 24) and 0xFF).toByte(),
                        ((len ushr 16) and 0xFF).toByte(),
                        ((len ushr 8) and 0xFF).toByte(),
                        (len and 0xFF).toByte()
                    )
                    outStream.write(header)
                    outStream.write(payload)
                    outStream.flush()
                }

                fun readFully(isStream: java.io.InputStream, size: Int): ByteArray {
                    val buf = ByteArray(size)
                    var offset = 0
                    while (offset < size) {
                        val read = isStream.read(buf, offset, size - offset)
                        if (read < 0) throw java.io.EOFException("Socket EOF reading $size bytes (got $offset)")
                        offset += read
                    }
                    return buf
                }

                fun readFramedRtsp(): String? {
                    val lenBuf = try {
                        readFully(inStream, 4)
                    } catch (e: Exception) {
                        return null
                    }
                    val len = ((lenBuf[0].toInt() and 0xFF) shl 24) or
                              ((lenBuf[1].toInt() and 0xFF) shl 16) or
                              ((lenBuf[2].toInt() and 0xFF) shl 8) or
                              (lenBuf[3].toInt() and 0xFF)
                    if (len <= 0 || len > 10 * 1024 * 1024) {
                        Log.e(TAG, "Illegal RTSP frame length from phone: $len")
                        return null
                    }
                    val rawPayload = readFully(inStream, len)
                    val plainBytes = if (rtspEncrypted) {
                        try {
                            decryptPayload(rawPayload)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to decrypt RTSP payload of size $len: ${e.message}")
                            return null
                        }
                    } else {
                        rawPayload
                    }
                    return String(plainBytes, StandardCharsets.UTF_8)
                }

                val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss aa EE", Locale.ENGLISH)
                val clientCSeq = AtomicInteger(1)
                var hasSentPlay = false
                var lastSetupCSeq = -1
                var streamUri = "rtsp://localhost/hisight1.1/streamid=0"

                // Step 1: Send ANNOUNCE request unencrypted to initiate negotiation
                val annCSeq = clientCSeq.getAndIncrement()
                val annBody = "encrypt_description: encrypt_list=aes128ctr;version=1;\r\ntraceid:0\r\n"
                val annBytes = annBody.toByteArray(StandardCharsets.UTF_8)
                val annReq = "ANNOUNCE * RTSP/1.0\r\n" +
                        "Date: ${dateFormat.format(Date())}\r\n" +
                        "CSeq: $annCSeq\r\n" +
                        "Content-Type: text/parameters\r\n" +
                        "Content-Length: ${annBytes.size}\r\n\r\n" +
                        annBody
                sendFramedRtsp(annReq, encrypt = false)

                while (running.get() && !socket.isClosed) {
                    val fullMsg = readFramedRtsp() ?: break
                    if (fullMsg.isEmpty()) continue

                    Log.i(TAG, "RX HiSight RTSP (enc=$rtspEncrypted, len=${fullMsg.length}):\n$fullMsg")

                    val doubleCrlf = if (fullMsg.contains("\r\n\r\n")) fullMsg.indexOf("\r\n\r\n") else fullMsg.indexOf("\n\n")
                    val headerSection = if (doubleCrlf >= 0) fullMsg.substring(0, doubleCrlf) else fullMsg
                    val body = if (doubleCrlf >= 0) fullMsg.substring(doubleCrlf + (if (fullMsg.contains("\r\n\r\n")) 4 else 2)) else ""

                    val lines = fullMsg.lines()
                    val firstLine = lines.firstOrNull()?.trim() ?: ""
                    val headers = mutableMapOf<String, String>()
                    for (line in lines) {
                        val colon = line.indexOf(':')
                        if (colon > 0) {
                            val k = line.substring(0, colon).trim().lowercase(Locale.ENGLISH)
                            val v = line.substring(colon + 1).trim()
                            headers[k] = v
                        }
                    }

                    val rxCSeq = headers["cseq"] ?: "1"

                    if (firstLine.startsWith("ANNOUNCE")) {
                        // Phone reverse ANNOUNCE! Reply unencrypted 200 OK then immediately activate AES-128-CTR
                        Log.i(TAG, "Phone reverse ANNOUNCE received (CSeq $rxCSeq). Replying 200 OK (unencrypted) and activating AES-128-CTR...")
                        val okResp = "RTSP/1.0 200 OK\r\n" +
                                "Date: ${dateFormat.format(Date())}\r\n" +
                                "Server: localhost\r\n" +
                                "CSeq: $rxCSeq\r\n\r\n"
                        sendFramedRtsp(okResp, encrypt = false)
                        rtspEncrypted = true
                        Log.i(TAG, "🔒 HiSight RTSP encryption (AES-128-CTR) activated!")
                    } else if (firstLine.startsWith("RTSP/1.0 200 OK")) {
                        val rxCSeqInt = rxCSeq.toIntOrNull() ?: -1
                        if (rxCSeqInt == lastSetupCSeq && !hasSentPlay) {
                            hasSentPlay = true
                            Log.i(TAG, "SETUP acknowledged with 200 OK! Sending PLAY request for $streamUri...")
                            val playCSeq = clientCSeq.getAndIncrement()
                            val sess = headers["session"]?.split(";")?.get(0)?.trim()
                            val sessHeader = if (!sess.isNullOrEmpty()) "Session: $sess\r\n" else ""
                            val playReq = "PLAY $streamUri RTSP/1.0\r\n" +
                                    "Date: ${dateFormat.format(Date())}\r\n" +
                                    "CSeq: $playCSeq\r\n" +
                                    sessHeader +
                                    "Range: npt=0.000-\r\n\r\n"
                            sendFramedRtsp(playReq)

                            // Parse TCP server_port if phone designated RTP/AVP/TCP
                            val serverPortMatch = Regex("server_port=(\\d+)", RegexOption.IGNORE_CASE).find(fullMsg)
                            if (serverPortMatch != null) {
                                val videoTcpPort = serverPortMatch.groupValues[1].toInt()
                                Log.i(TAG, "🎯 Phone designated video stream TCP port: $videoTcpPort! Connecting TCP stream receiver to $phoneIp:$videoTcpPort...")
                                videoDecoder.setSessionKey(sessionKey)
                                startTcpStreamReceiver(phoneIp, videoTcpPort, sessionKey)
                            } else {
                                Log.i(TAG, "Phone did not specify server_port, relying on UDP receiver on port 50000")
                            }

                            // Parse remotectl_port for RemoteControl channel (mandatory for phone to transition to streaming)
                            val rcPortMatch = Regex("remotectl_port=(\\d+)", RegexOption.IGNORE_CASE).find(fullMsg)
                            if (rcPortMatch != null) {
                                val rcPort = rcPortMatch.groupValues[1].toInt()
                                Log.i(TAG, "🎮 Phone designated RemoteControl TCP port: $rcPort! Connecting RemoteControl receiver...")
                                startControlStreamReceiver(phoneIp, rcPort)
                            }
                        } else {
                            Log.i(TAG, "RTSP 200 OK acknowledged for CSeq $rxCSeq")
                        }
                    } else if (firstLine.startsWith("GET_PARAMETER")) {
                        // Phone M3 or M10 KeepAlive
                        if (body.contains("his_video_formats") || fullMsg.contains("his_video_formats") ||
                            body.contains("his_version") || fullMsg.contains("his_version")) {
                            Log.i(TAG, "Phone M3 GET_PARAMETER received. Replying with video/device capabilities...")
                            val capBody = StringBuilder().apply {
                                append("his_version: 1.0\r\n")
                                append("his_device_type: device_type 4;subtype 0;\r\n")
                                append("his_support_temp_notify: 0\r\n")
                                append("his_audio_codecs: 1\r\n")
                                append("his_media_capability: 0\r\n")
                                append("his_player_controller_capability: 0\r\n")
                                append("his_uibc_capability: input_category_list=GENERIC;generic_cap_list=left_point_down, left_point_up, left_move, left_key_down, left_key_up, mouse_down, mouse_up, mouse_move;\r\n")
                                // Crucial: height must be at end without trailing semicolon for AirSharing parser
                                append("his_video_formats: codecs 1;fps 60;width 1920;gop 60;dpi 160;bitrate 10000000;asymmetric 0;height 1080\r\n")
                            }.toString()
                            val capBytes = capBody.toByteArray(StandardCharsets.UTF_8)
                            val resp = "RTSP/1.0 200 OK\r\n" +
                                    "Date: ${dateFormat.format(Date())}\r\n" +
                                    "Server: localhost\r\n" +
                                    "CSeq: $rxCSeq\r\n" +
                                    "Content-Type: text/parameters\r\n" +
                                    "Content-Length: ${capBytes.size}\r\n\r\n" +
                                    capBody
                            sendFramedRtsp(resp)
                        } else {
                            // Keepalive or simple GET_PARAMETER (M10)
                            Log.i(TAG, "Phone M10 KeepAlive GET_PARAMETER received. Replying 200 OK...")
                            sendFramedRtsp("RTSP/1.0 200 OK\r\nDate: ${dateFormat.format(Date())}\r\nServer: localhost\r\nCSeq: $rxCSeq\r\n\r\n")
                        }
                    } else if (firstLine.startsWith("SET_PARAMETER")) {
                        // Phone M4 or M5
                        Log.i(TAG, "Phone SET_PARAMETER received (CSeq $rxCSeq). Replying 200 OK...")
                        sendFramedRtsp("RTSP/1.0 200 OK\r\nDate: ${dateFormat.format(Date())}\r\nServer: localhost\r\nCSeq: $rxCSeq\r\n\r\n")

                        val urlMatch = Regex("his_presentation_URL:\\s*(\\S+)", RegexOption.IGNORE_CASE).find(fullMsg)
                        if (urlMatch != null) {
                            streamUri = urlMatch.groupValues[1]
                            Log.i(TAG, "Phone requested presentation URL: $streamUri")
                        }

                        if (body.contains("his_trigger_method: SETUP") || body.contains("his_trigger_method:SETUP") ||
                            fullMsg.contains("his_trigger_method: SETUP") || fullMsg.contains("his_trigger_method:SETUP")) {
                            Log.i(TAG, "Phone M5 requested SETUP! Sending SETUP request for $streamUri...")
                            val setupCSeq = clientCSeq.getAndIncrement()
                            lastSetupCSeq = setupCSeq
                            val setupReq = "SETUP $streamUri RTSP/1.0\r\n" +
                                    "Date: ${dateFormat.format(Date())}\r\n" +
                                    "CSeq: $setupCSeq\r\n" +
                                    "Transport: RTP/AVP/TCP;unicast;client_port=50000\r\n\r\n"
                            sendFramedRtsp(setupReq)
                        }
                    } else if (firstLine.startsWith("OPTIONS")) {
                        sendFramedRtsp("RTSP/1.0 200 OK\r\nDate: ${dateFormat.format(Date())}\r\nServer: localhost\r\nCSeq: $rxCSeq\r\nPublic: hisight1.0, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER\r\n\r\n")
                    } else if (firstLine.startsWith("RENDER_READY")) {
                        sendFramedRtsp("RTSP/1.0 200 OK\r\nDate: ${dateFormat.format(Date())}\r\nServer: localhost\r\nCSeq: $rxCSeq\r\n\r\n")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "HiSight RTSP client exception: ${e.message}", e)
            } finally {
                try { rtspSocket?.close() } catch (_: Exception) {}
            }
        }
    }

    private fun startTcpStreamReceiver(phoneIp: String, port: Int, sessionKey: ByteArray) {
        executor.submit {
            Log.i(TAG, "=== Starting Video TCP Stream Receiver connecting to $phoneIp:$port ===")
            var streamSock: java.net.Socket? = null
            try {
                var connected = false
                for (retry in 1..20) {
                    try {
                        val s = java.net.Socket()
                        s.reuseAddress = true
                        try {
                            s.bind(java.net.InetSocketAddress(50000))
                            Log.i(TAG, "Video TCP Stream bound to local port 50000 (matches client_port in SETUP)")
                        } catch (be: Exception) {
                            Log.w(TAG, "Could not bind to local port 50000: ${be.message}")
                        }
                        s.connect(java.net.InetSocketAddress(phoneIp, port), 2000)
                        s.tcpNoDelay = true
                        s.receiveBufferSize = 8 * 1024 * 1024
                        streamSock = s
                        connected = true
                        Log.i(TAG, "✅ Video TCP Stream Connected (localPort=${s.localPort}) to $phoneIp:$port on attempt $retry!")
                        break
                    } catch (e: Exception) {
                        Log.w(TAG, "Video TCP Stream connect attempt $retry failed: ${e.message}, retrying in 100ms...")
                        Thread.sleep(100)
                    }
                }
                if (!connected || streamSock == null) {
                    Log.e(TAG, "Failed to connect to Video TCP Stream at $phoneIp:$port after retries")
                    return@submit
                }

                videoTcpSocket?.close()
                videoTcpSocket = streamSock
                val inStream = streamSock.getInputStream()

                val keySpec = SecretKeySpec(sessionKey.copyOfRange(0, 16), "AES")
                var frameCount = 0L
                var totalBytes = 0L

                fun readExact(isStream: java.io.InputStream, size: Int): ByteArray {
                    val buf = ByteArray(size)
                    var off = 0
                    while (off < size) {
                        val r = isStream.read(buf, off, size - off)
                        if (r < 0) throw java.io.EOFException("Video stream EOF ($off/$size bytes read)")
                        off += r
                    }
                    return buf
                }

                while (running.get() && !streamSock.isClosed) {
                    val lenBuf = try {
                        readExact(inStream, 4)
                    } catch (e: Exception) {
                        Log.i(TAG, "Video TCP stream disconnected/closed: ${e.message}")
                        break
                    }

                    val frameLen = ((lenBuf[0].toInt() and 0xFF) shl 24) or
                                   ((lenBuf[1].toInt() and 0xFF) shl 16) or
                                   ((lenBuf[2].toInt() and 0xFF) shl 8) or
                                   (lenBuf[3].toInt() and 0xFF)

                    if (frameLen <= 0 || frameLen > 10 * 1024 * 1024) {
                        Log.w(TAG, "Video TCP invalid frame length: $frameLen")
                        break
                    }

                    val frameData = readExact(inStream, frameLen)
                    frameCount++
                    totalBytes += frameLen

                    if (frameCount <= 10 || frameCount % 300 == 0L) {
                        val previewHex = frameData.take(minOf(frameLen, 64)).joinToString("") { "%02x".format(it) }
                        Log.i(TAG, "📹 RX Video TCP frame #$frameCount ($frameLen B, total ${totalBytes}B): hex=$previewHex")
                    }

                    val b0 = frameData[0].toInt() and 0xFF
                    if ((b0 and 0xC0) == 0x80) {
                        // Plain RTP packet
                        videoDecoder.onRtpPacket(frameData, 0, frameData.size)
                    } else if (frameLen >= 16) {
                        // Attempt AES-128-CTR decryption (IV 16 B + cipher)
                        try {
                            val iv = frameData.copyOfRange(0, 16)
                            val cipherBytes = frameData.copyOfRange(16, frameData.size)
                            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                            cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
                            val plainBytes = cipher.doFinal(cipherBytes)

                            val plainB0 = plainBytes.firstOrNull()?.toInt()?.and(0xFF) ?: 0
                            if (frameCount <= 5) {
                                val plainHex = plainBytes.take(minOf(plainBytes.size, 24)).joinToString("") { "%02x".format(it) }
                                Log.i(TAG, "🔓 Decrypted frame #$frameCount (${plainBytes.size} B): b0=0x${"%02x".format(plainB0)}, hex=$plainHex")
                            }

                            if ((plainB0 and 0xC0) == 0x80) {
                                videoDecoder.onRtpPacket(plainBytes, 0, plainBytes.size)
                            } else if (plainBytes.size >= 4 && plainBytes[0] == 0.toByte() && plainBytes[1] == 0.toByte() && plainBytes[2] == 0.toByte() && plainBytes[3] == 1.toByte()) {
                                videoDecoder.feedRawH264(plainBytes, 0, plainBytes.size)
                            } else {
                                videoDecoder.onRtpPacket(plainBytes, 0, plainBytes.size)
                            }
                        } catch (e: Exception) {
                            if (frameCount <= 5) {
                                Log.w(TAG, "Decryption error on frame #$frameCount: ${e.message}")
                            }
                            videoDecoder.onRtpPacket(frameData, 0, frameData.size)
                        }
                    } else {
                        videoDecoder.onRtpPacket(frameData, 0, frameData.size)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Video TCP Stream Receiver error: ${e.message}", e)
            } finally {
                try { streamSock?.close() } catch (_: Exception) {}
            }
        }
    }

    private fun startControlStreamReceiver(phoneIp: String, port: Int) {
        executor.submit {
            Log.i(TAG, "=== Starting RemoteControl TCP connecting to $phoneIp:$port ===")
            var rcSock: java.net.Socket? = null
            try {
                for (retry in 1..20) {
                    try {
                        val sock = java.net.Socket()
                        sock.connect(java.net.InetSocketAddress(phoneIp, port), 2000)
                        sock.tcpNoDelay = true
                        rcSock = sock
                        synchronized(controlLock) {
                            try { controlTcpSocket?.close() } catch (_: Exception) {}
                            controlTcpSocket = sock
                        }
                        Log.i(TAG, "🎮 RemoteControl TCP Connected to $phoneIp:$port on attempt $retry!")
                        break
                    } catch (e: Exception) {
                        Thread.sleep(100)
                    }
                }
                if (rcSock == null) {
                    Log.e(TAG, "Failed to connect to RemoteControl TCP server at $phoneIp:$port")
                    return@submit
                }

                val inStream = rcSock.getInputStream()
                val buf = ByteArray(4096)
                while (running.get() && !rcSock.isClosed) {
                    val r = inStream.read(buf)
                    if (r < 0) break
                    Log.i(TAG, "🕹️ RX RemoteControl data ($r bytes)")
                }
            } catch (e: Exception) {
                Log.w(TAG, "RemoteControl TCP exception: ${e.message}")
            } finally {
                synchronized(controlLock) {
                    if (controlTcpSocket == rcSock) {
                        controlTcpSocket = null
                    }
                }
                try { rcSock?.close() } catch (_: Exception) {}
            }
        }
    }

    /**
     * Send encrypted reverse touch event to phone over RemoteControl TCP socket.
     * action: 0 = ACTION_DOWN, 1 = ACTION_UP, 2 = ACTION_MOVE
     * x: 0..1920 (HiCar virtual display width)
     * y: 0..1080 (HiCar virtual display height)
     */
    fun sendTouchEvent(action: Int, x: Int, y: Int) {
        executor.submit {
            try {
                val sock = synchronized(controlLock) { controlTcpSocket }
                if (sock == null || sock.isClosed) {
                    Log.w(TAG, "Cannot send touch event: controlTcpSocket is not connected")
                    return@submit
                }
                val sessionKey = btServer.getSessionKey()
                if (sessionKey == null) {
                    Log.w(TAG, "Cannot send touch event: sessionKey is null")
                    return@submit
                }

                val clampedX = x.coerceIn(0, 1920)
                val clampedY = y.coerceIn(0, 1080)

                // Plaintext payload (15 bytes):
                // Bytes 0..5: 6 reserved / timestamp bytes (all 0)
                // Bytes 6..14: 9-byte generic touch inputBody:
                //   byte 6: action (0 = DOWN, 1 = UP, 2 = MOVE)
                //   byte 7..8: bodyLen = 6 (1 byte numPointers + 5 bytes pointer info)
                //   byte 9: numPointers = 1 (crucial: must NOT be 0!)
                //   byte 10: pointerId = 0
                //   byte 11..12: X coordinate (16-bit big-endian)
                //   byte 13..14: Y coordinate (16-bit big-endian)
                val plain = ByteArray(15)
                plain[6] = action.toByte() // 0 = DOWN, 1 = UP, 2 = MOVE
                plain[7] = 0x00            // bodyLen high byte
                plain[8] = 0x06            // bodyLen low byte (6)
                plain[9] = 0x01            // numPointers = 1
                plain[10] = 0x00           // pointerId = 0
                plain[11] = (clampedX shr 8).toByte()
                plain[12] = (clampedX and 0xFF).toByte()
                plain[13] = (clampedY shr 8).toByte()
                plain[14] = (clampedY and 0xFF).toByte()

                val iv = ByteArray(16).apply { touchRandom.nextBytes(this) }
                val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(sessionKey.copyOfRange(0, 16), "AES"),
                    IvParameterSpec(iv)
                )
                val cipherText = cipher.doFinal(plain) // 15 bytes

                // 35-byte packet on the wire:
                // Bytes 0..3: 4-byte header (category=0, type=0, totalLen=35)
                // Bytes 4..19: 16-byte random IV
                // Bytes 20..34: 15-byte AES-128-CTR ciphertext
                val packet = ByteArray(35)
                packet[0] = 0x00 // categoryType = 0 (generic input)
                packet[1] = 0x00 // payloadType = 0
                packet[2] = 0x00 // totalLength = 35 (0x0023)
                packet[3] = 0x23
                System.arraycopy(iv, 0, packet, 4, 16)
                System.arraycopy(cipherText, 0, packet, 20, 15)

                synchronized(controlLock) {
                    val out = sock.getOutputStream()
                    out.write(packet)
                    out.flush()
                }
                Log.d(TAG, "🎮 Sent touch event: action=$action, pos=($clampedX, $clampedY)")
            } catch (e: Exception) {
                Log.e(TAG, "Error sending touch event: ${e.message}")
            }
        }
    }

    /**
     * Synthesize a full tap (DOWN followed by UP) at (x, y).
     */
    fun sendClick(x: Int, y: Int) {
        sendTouchEvent(0, x, y)
        executor.submit {
            try { Thread.sleep(60) } catch (_: Exception) {}
            sendTouchEvent(1, x, y)
        }
    }

    private fun startUdpReceiver(port: Int) {
        executor.submit {
            try {
                udpSocket?.close()
                val ds = java.net.DatagramSocket(port)
                udpSocket = ds
                Log.i(TAG, "UDP Media Receiver listening on port $port")
                val buf = ByteArray(65535)
                var packetCount = 0
                var byteCount = 0L
                while (running.get() && !ds.isClosed) {
                    val p = java.net.DatagramPacket(buf, buf.size)
                    ds.receive(p)
                    packetCount++
                    byteCount += p.length
                    videoDecoder.onRtpPacket(buf, 0, p.length)
                    if (packetCount <= 10 || packetCount % 100 == 0) {
                        Log.i(TAG, "RX UDP RTP packet #$packetCount (${p.length} B) total=${byteCount}B from ${p.address}:${p.port}: hex=${buf.take(minOf(p.length, 32)).joinToString("") { "%02x".format(it) }}")
                    }
                }
            } catch (e: Exception) {
                if (running.get()) Log.e(TAG, "UDP receiver error on port $port: ${e.message}")
            }
        }
    }

    // ─── mDNS ─────────────────────────────────────────────────────────────────

    private fun registerMdns() {
        val serviceInfo = NsdServiceInfo().apply {
            serviceName = SERVICE_NAME
            serviceType = SERVICE_TYPE
            port = TCP_PORT
        }

        registrationListener = object : NsdManager.RegistrationListener {
            override fun onRegistrationFailed(si: NsdServiceInfo, errorCode: Int) {
                callback.onMdnsStatusChanged(false, "mDNS registration failed (code $errorCode)")
                Log.e(TAG, "mDNS registration failed: $errorCode")
            }

            override fun onUnregistrationFailed(si: NsdServiceInfo, errorCode: Int) {
                Log.e(TAG, "mDNS unregistration failed: $errorCode")
            }

            override fun onServiceRegistered(si: NsdServiceInfo) {
                val name = si.serviceName
                callback.onMdnsStatusChanged(
                    true,
                    "Port $TCP_PORT | Registered as \"$name\""
                )
                Log.i(TAG, "mDNS registered: $name")
            }

            override fun onServiceUnregistered(si: NsdServiceInfo) {
                callback.onMdnsStatusChanged(false, "mDNS unregistered")
                Log.i(TAG, "mDNS unregistered")
            }
        }

        try {
            nsdManager.registerService(
                serviceInfo,
                NsdManager.PROTOCOL_DNS_SD,
                registrationListener
            )
        } catch (e: Exception) {
            callback.onMdnsStatusChanged(false, "mDNS error: ${e.message}")
            Log.e(TAG, "mDNS register exception: ${e.message}")
        }
    }

    private fun unregisterMdns() {
        registrationListener?.let {
            try {
                nsdManager.unregisterService(it)
            } catch (_: Exception) {}
            registrationListener = null
        }
    }
}
