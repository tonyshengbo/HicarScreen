package com.hicar.explorer

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pGroup
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Looper
import android.util.Base64
import android.util.Log
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections
import java.util.UUID
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * HiCarBtServer – Handles GATT Server, FE35 SDP Listener, and HiCar RFCOMM Handshake + Hichain DeviceAuth.
 *
 * Reverse-Engineered Constants:
 *  - GATT Service UUID:        d01ef33b-d575-df62-470f-96673d05bd9b
 *  - GATT Characteristic UUID: cfea78cd-3a32-dcf6-a11c-12602f48510b
 *  - SDP Search UUID:          0000FE35-0000-1000-8000-00805F9B34FB
 *  - RFCOMM Server UUID:       FA87C0D0-AFAC-11DE-8A39-0800200C9A66
 *  - Nearby PC Server UUID:    9664AA26-D76C-43AD-9775-D310F253A408
 *  - SPP Server UUID:          00001101-0000-1000-8000-00805F9B34FB
 *  - AES-128 Key:              "yzjED4s9CpIp3mwA"
 *  - Model ID:                 "00049200"
 *  - Handshake version string: "14.2.0.400,00049200"
 *  - Default PIN:              "123456"
 */
class HiCarBtServer(
    private val context: Context,
    private val callback: Callback
) {

    interface Callback {
        fun onStatus(detail: String)
        fun onRfcommData(source: String, data: ByteArray)
    }

    companion object {
        private const val TAG = "HiCarBtServer"

        val GATT_SERVICE_UUID: UUID = UUID.fromString("d01ef33b-d575-df62-470f-96673d05bd9b")
        val GATT_CHAR_UUID: UUID = UUID.fromString("cfea78cd-3a32-dcf6-a11c-12602f48510b")
        val SDP_FE35_UUID: UUID = UUID.fromString("0000FE35-0000-1000-8000-00805F9B34FB")
        val RFCOMM_UUID: UUID = UUID.fromString("FA87C0D0-AFAC-11DE-8A39-0800200C9A66")
        val PC_UUID: UUID = UUID.fromString("9664AA26-D76C-43AD-9775-D310F253A408")
        val SPP_UUID: UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
        val FD9A_UUID: UUID = UUID.fromString("0000FD9A-0000-1000-8000-00805F9B34FB")

        const val AES_KEY = "yzjED4s9CpIp3mwA"
        const val MODEL_ID = "00049200"
        const val VERSION_CONTENT = "14.2.0.400,00049200"
        const val PIN_CODE = "123456"

        private const val MODP_2048_HEX =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
        private val MODP_P = BigInteger(MODP_2048_HEX, 16)

        private val CRC_TABLE = intArrayOf(
            0, 49345, 49537, 320, 49921, 960, 640, 49729, 50689, 1728, 1920, 51009, 1280, 50625, 50305, 1088,
            52225, 3264, 3456, 52545, 3840, 53185, 52865, 3648, 2560, 51905, 52097, 2880, 51457, 2496, 2176, 51265,
            55297, 6336, 6528, 55617, 6912, 56257, 55937, 6720, 7680, 57025, 57217, 8000, 56577, 7616, 7296, 56385,
            5120, 54465, 54657, 5440, 55041, 6080, 5760, 54849, 53761, 4800, 4992, 54081, 4352, 53697, 53377, 4160,
            61441, 12480, 12672, 61761, 13056, 62401, 62081, 12864, 13824, 63169, 63361, 14144, 62721, 13760, 13440, 62529,
            15360, 64705, 64897, 15680, 65281, 16320, 16000, 65089, 64001, 15040, 15232, 64321, 14592, 63937, 63617, 14400,
            10240, 59585, 59777, 10560, 60161, 11200, 10880, 59969, 60929, 11968, 12160, 61249, 11520, 60865, 60545, 11328,
            58369, 9408, 9600, 58689, 9984, 59329, 59009, 9792, 8704, 58049, 58241, 9024, 57601, 8640, 8320, 57409,
            40961, 24768, 24960, 41281, 25344, 41921, 41601, 25152, 26112, 42689, 42881, 26432, 42241, 26048, 25728, 42049,
            27648, 44225, 44417, 27968, 44801, 28608, 28288, 44609, 43521, 27328, 27520, 43841, 26880, 43457, 43137, 26688,
            30720, 47297, 47489, 31040, 47873, 31680, 31360, 47681, 48641, 32448, 32640, 48961, 32000, 48577, 48257, 31808,
            46081, 29888, 30080, 46401, 30464, 47041, 46721, 30272, 29184, 45761, 45953, 29504, 45313, 29120, 28800, 45121,
            20480, 37057, 37249, 20800, 37633, 21440, 21120, 37441, 38401, 22208, 22400, 38721, 21760, 38337, 38017, 21568,
            39937, 23744, 23936, 40257, 24320, 40897, 40577, 24128, 23040, 39617, 39809, 23360, 39169, 22976, 22656, 38977,
            34817, 18624, 18816, 35137, 19200, 35777, 35457, 19008, 19968, 36545, 36737, 20288, 36097, 19904, 19584, 35905,
            17408, 33985, 34177, 17728, 34561, 18368, 18048, 34369, 33281, 17088, 17280, 33601, 16640, 33217, 32897, 16448
        )
    }

    private val bluetoothManager: BluetoothManager? =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager?.adapter

    private var gattServer: BluetoothGattServer? = null
    private val serverSockets = Collections.synchronizedList(mutableListOf<BluetoothServerSocket>())
    private val running = AtomicBoolean(false)
    private val executor: ExecutorService = Executors.newCachedThreadPool()

    // Hichain Auth State
    private var pakeCarSalt: ByteArray? = null
    private var pakeCarChallenge: ByteArray? = null
    private var pakeCarPriv: BigInteger? = null
    private var pakePhoneChallenge: ByteArray? = null
    private var pakeSessionKey: ByteArray? = null
    private var dmsdpSessionKey: ByteArray? = null
    private var peerRandom: ByteArray? = null
    private var peerId: ByteArray? = null
    private var selfRandom: ByteArray? = null
    private val selfId: ByteArray by lazy { getDeviceSummary().toByteArray(StandardCharsets.UTF_8) }
    private var psk: ByteArray? = null
    private var sessionKey: ByteArray? = null
    private var dataServerPort: Int = -1

    fun getSessionKey(): ByteArray? = dmsdpSessionKey ?: pakeSessionKey ?: sessionKey?.copyOfRange(0, 16)

    // Wi-Fi P2P Group Owner state
    private var wifiP2pManager: WifiP2pManager? = null
    private var wifiP2pChannel: WifiP2pManager.Channel? = null
    private var p2pSsid: String = "DIRECT-HiCar-Pixel"
    private var p2pPsk: String = "12345678"
    private var p2pFreq: Int = 5180
    private var p2pGoMac: String = "02:00:00:00:00:00"
    private var p2pGroupCreated: Boolean = false

    private val pairingReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == BluetoothDevice.ACTION_PAIRING_REQUEST) {
                val dev = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
                val variant = intent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT, -1)
                Log.i(TAG, "Auto-confirming ACTION_PAIRING_REQUEST variant=$variant from ${dev?.address}")
                callback.onStatus("Auto-confirmed BT pairing: ${dev?.address}")
                try {
                    dev?.setPairingConfirmation(true)
                    abortBroadcast()
                } catch (e: Exception) {
                    Log.w(TAG, "Auto-pair error: ${e.message}")
                }
            }
        }
    }

    fun start() {
        if (running.getAndSet(true)) return

        try {
            val filter = IntentFilter(BluetoothDevice.ACTION_PAIRING_REQUEST).apply {
                priority = IntentFilter.SYSTEM_HIGH_PRIORITY
            }
            context.registerReceiver(pairingReceiver, filter)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register pairing receiver: ${e.message}")
        }

        enableDiscoverable()
        startGattServer()
        initP2pGroup()

        // Listen on INSECURE RFCOMM to match Huawei Nearby's createInsecureRfcommSocket
        startRfcommListener(SDP_FE35_UUID, "NearbyServerSocket", insecure = true)
        startRfcommListener(RFCOMM_UUID, "HiCar_RFCOMM", insecure = true)
        startRfcommListener(PC_UUID, "NearbyPcServerSocket", insecure = true)
        startRfcommListener(SPP_UUID, "SerialPort", insecure = true)
        startRfcommListener(FD9A_UUID, "HuaweiFastPair_FD9A", insecure = true)
    }

    fun stop() {
        running.set(false)
        try { wifiP2pManager?.removeGroup(wifiP2pChannel, null) } catch (ignored: Exception) {}
        try { context.unregisterReceiver(p2pReceiver) } catch (ignored: Exception) {}
        try { context.unregisterReceiver(pairingReceiver) } catch (ignored: Exception) {}
        try { gattServer?.close() } catch (ignored: Exception) {}
        synchronized(serverSockets) {
            for (s in serverSockets) {
                try { s.close() } catch (ignored: Exception) {}
            }
            serverSockets.clear()
        }
    }

    private fun unbondExistingDevices() {
        try {
            val adapter = bluetoothAdapter ?: return
            val bonded = adapter.bondedDevices ?: return
            for (dev in bonded) {
                val name = try { dev.name ?: "" } catch (e: SecurityException) { "" }
                if (name.contains("Mate", ignoreCase = true) || name.contains("Huawei", ignoreCase = true) || name.contains("tony", ignoreCase = true)) {
                    val method = dev.javaClass.getMethod("removeBond")
                    method.invoke(dev)
                    Log.i(TAG, "Unbonded stale device: $name (${dev.address})")
                    callback.onStatus("Unbonded stale device: $name")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Unbond check error: ${e.message}")
        }
    }

    private fun enableDiscoverable() {
        try {
            val adapter = bluetoothAdapter ?: return
            val method = adapter.javaClass.getMethod("setScanMode", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            method.invoke(adapter, BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE, 3600)
            Log.i(TAG, "Set Bluetooth scan mode to CONNECTABLE_DISCOVERABLE (3600s)")
            callback.onStatus("BT discoverable & connectable enabled")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to set discoverable: ${e.message}")
        }
    }

    private fun startGattServer() {
        val bm = bluetoothManager ?: return
        try {
            gattServer = bm.openGattServer(context, object : BluetoothGattServerCallback() {
                override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
                    val stateStr = if (newState == BluetoothGatt.STATE_CONNECTED) "Connected" else "Disconnected"
                    callback.onStatus("GATT ${device?.name ?: device?.address} $stateStr")
                    Log.i(TAG, "GATT device $stateStr: ${device?.address}")
                }

                override fun onMtuChanged(device: BluetoothDevice?, mtu: Int) {
                    Log.i(TAG, "GATT MTU changed to $mtu for ${device?.address}")
                    callback.onStatus("GATT MTU: $mtu")
                }

                override fun onCharacteristicReadRequest(
                    device: BluetoothDevice?,
                    requestId: Int,
                    offset: Int,
                    characteristic: BluetoothGattCharacteristic?
                ) {
                    Log.i(TAG, "GATT ReadRequest char=${characteristic?.uuid} reqId=$requestId offset=$offset from ${device?.address}")
                    if (characteristic?.uuid == GATT_CHAR_UUID) {
                        val payload = buildEncryptedPayload()
                        val responseValue = if (offset < payload.size) {
                            payload.copyOfRange(offset, payload.size)
                        } else {
                            ByteArray(0)
                        }
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, responseValue)
                        callback.onStatus("GATT Read offset=$offset [${responseValue.size}B of ${payload.size}B]")
                        Log.i(TAG, "Served encrypted CarDeviceInfo offset=$offset size=${responseValue.size}/${payload.size} to ${device?.address}")
                    } else {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                    }
                }
            })

            val service = BluetoothGattService(GATT_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            val characteristic = BluetoothGattCharacteristic(
                GATT_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            service.addCharacteristic(characteristic)
            gattServer?.addService(service)
            callback.onStatus("GATT Server active | UUID: d01ef33b")
            Log.i(TAG, "HiCar GATT server started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start GATT server: ${e.message}")
            callback.onStatus("GATT error: ${e.message}")
        }
    }

    private fun getServerPort(serverSocket: BluetoothServerSocket): Int {
        return try {
            val socketField = serverSocket.javaClass.getDeclaredField("mSocket").apply { isAccessible = true }
            val btSocket = socketField.get(serverSocket) as BluetoothSocket
            val portField = btSocket.javaClass.getDeclaredField("mPort").apply { isAccessible = true }
            portField.getInt(btSocket)
        } catch (e: Exception) {
            try {
                val method = serverSocket.javaClass.getDeclaredMethod("getChannel").apply { isAccessible = true }
                (method.invoke(serverSocket) as? Int) ?: -1
            } catch (e2: Exception) {
                try {
                    val field = serverSocket.javaClass.getDeclaredField("mChannel").apply { isAccessible = true }
                    field.getInt(serverSocket)
                } catch (e3: Exception) {
                    -1
                }
            }
        }
    }

    private fun startRfcommListener(uuid: UUID, serviceName: String, insecure: Boolean) {
        val adapter = bluetoothAdapter ?: return
        executor.execute {
            try {
                val serverSocket = if (insecure) {
                    adapter.listenUsingInsecureRfcommWithServiceRecord(serviceName, uuid)
                } else {
                    adapter.listenUsingRfcommWithServiceRecord(serviceName, uuid)
                }
                serverSockets.add(serverSocket)
                val channel = getServerPort(serverSocket)
                if (serviceName == "HiCar_RFCOMM") {
                    dataServerPort = channel
                    Log.i(TAG, "Designated dataServerPort = $dataServerPort ($serviceName)")
                } else if (serviceName == "NearbyServerSocket" && dataServerPort <= 0) {
                    dataServerPort = channel
                }
                val secStr = if (insecure) "Insecure" else "Secure"
                callback.onStatus("RFCOMM [$secStr] listening: $serviceName (ch=$channel)")
                Log.i(TAG, "RFCOMM server started [$secStr] on $uuid ($serviceName, ch=$channel)")

                while (running.get()) {
                    val socket: BluetoothSocket = try {
                        serverSocket.accept()
                    } catch (e: IOException) {
                        if (!running.get()) break
                        Log.w(TAG, "RFCOMM accept error on $serviceName ($secStr): ${e.message}")
                        break
                    }

                    val dev = socket.remoteDevice
                    val devName = try { dev?.name ?: dev?.address ?: "Unknown" } catch (e: SecurityException) { "Unknown" }
                    val label = "$serviceName($secStr):$devName"
                    callback.onStatus("RFCOMM connected: $label")
                    Log.i(TAG, "RFCOMM client connected: $label")

                    handleRfcommClient(socket, label)
                }
            } catch (e: SecurityException) {
                callback.onStatus("RFCOMM permission error: ${e.message}")
            } catch (e: Exception) {
                callback.onStatus("RFCOMM error ($serviceName): ${e.message}")
            }
        }
    }

    private fun handleRfcommClient(socket: BluetoothSocket, clientName: String) {
        executor.execute {
            handleStream(socket.inputStream, socket.outputStream, clientName) {
                try { socket.close() } catch (ignored: Exception) {}
            }
        }
    }

    fun handleStream(
        input: InputStream,
        out: OutputStream,
        clientName: String,
        onData: (ByteArray) -> Unit = {},
        onDisconnect: () -> Unit = {}
    ) {
        try {
            val buffer = ByteArray(8192)
            while (running.get()) {
                val count = input.read(buffer)
                if (count < 0) break
                val data = buffer.copyOf(count)
                callback.onRfcommData(clientName, data)
                onData(data)

                // Check if this is an RTSP or DMSDP command / response
                val text = String(data, StandardCharsets.UTF_8)
                if (text.startsWith("OPTIONS ") || text.startsWith("DESCRIBE ") ||
                    text.startsWith("SETUP ") || text.startsWith("PLAY ") ||
                    text.startsWith("TEARDOWN ") || text.startsWith("GET_PARAMETER") ||
                    text.startsWith("SET_PARAMETER") || text.startsWith("TRIGGER_DEVICE_DOWN") ||
                    text.startsWith("RESETUP") || text.startsWith("DMSDP/") || text.startsWith("RTSP/")) {
                    Log.i(TAG, "RX RTSP/DMSDP from $clientName:\n$text")
                    handleRtsp(text, out, clientName)
                    continue
                }

                // Check if this is a framed packet (magic byte 0x7F)
                if (data[0] == 0x7F.toByte()) {
                    val moduleId = data[1].toInt() and 0xFF
                    Log.i(TAG, "RX Frame starting with 0x7F, module=$moduleId from $clientName: ${toHex(data)}")

                    if (moduleId == 0x80) { // Module 0: CCMP Handshake
                        val ccmpResp = buildCcmpResponse()
                        out.write(ccmpResp)
                        out.flush()
                        Log.i(TAG, "TX CCMP response to $clientName: ${toHex(ccmpResp)}")
                        callback.onStatus("TX CCMP response (${ccmpResp.size}B)")
                    } else if (moduleId == 0x81) { // Module 1: TokenManager / Trust Engine
                        Log.i(TAG, "RX Module 1 (TokenManager) frame from $clientName: ${toHex(data)}")
                        // Reply with Module 1 Token ACK specifying DMSDP Control Port (9999)
                        // Payload: byte[0]=0, byte[1..2]=port (9999 = 0x270F), byte[3..15]=0
                        val ctrlPort = 9999
                        val payload = ByteArray(16) { 0 }
                        payload[0] = 0x00
                        payload[1] = ((ctrlPort shr 8) and 0xFF).toByte()
                        payload[2] = (ctrlPort and 0xFF).toByte()

                        val header = byteArrayOf(0x7F.toByte(), 0x81.toByte(), 0x90.toByte())
                        val pktNoCrc = header + payload
                        val crc = crc16(pktNoCrc, pktNoCrc.size)
                        val tokenAck = pktNoCrc + byteArrayOf((crc and 0xFF).toByte(), ((crc ushr 8) and 0xFF).toByte())

                        out.write(tokenAck)
                        out.flush()
                        Log.i(TAG, "TX Module 1 response (ctrlPort=$ctrlPort) to $clientName: ${toHex(tokenAck)}")
                        callback.onStatus("TX Module 1 Token ACK (port $ctrlPort)")
                    } else if (moduleId == 0x82) { // Module 2: Business Negotiation
                        val negResp = buildNegotiationResponse()
                        out.write(negResp)
                        out.flush()
                        Log.i(TAG, "TX Module 2 negotiation response to $clientName: ${toHex(negResp)}")
                        callback.onStatus("TX Negotiation response (${negResp.size}B)")
                    } else if (moduleId == 0x84) { // Module 4: ResourceManager / Wi-Fi P2P Channel Negotiation
                        Log.i(TAG, "RX Module 4 (ResourceManager) frame from $clientName: ${toHex(data)}")
                        handleModule4Frame(data, out, clientName)
                    } else if (moduleId == 0xA1) { // Module 33: P2pChannelStateMachine
                        Log.i(TAG, "RX Module 33 (P2pChannelStateMachine) frame from $clientName: ${toHex(data)}")
                        handleModule33Frame(data, out, clientName)
                    } else {
                        Log.w(TAG, "RX unknown 0x7F module: $moduleId from $clientName")
                    }

                    // Check if buffer also contains JSON
                    val jsonIdx = data.indexOf('{'.code.toByte())
                    if (jsonIdx >= 0) {
                        val jsonText = String(data, jsonIdx, data.size - jsonIdx, StandardCharsets.UTF_8)
                        handleIncomingPayload(jsonText, out, clientName)
                    }
                } else {
                    Log.i(TAG, "RX non-0x7F from $clientName (${data.size}B): hex=${toHex(data.take(64).toByteArray())} text=${text.take(128)}")
                    handleIncomingPayload(text, out, clientName)
                }
            }
        } catch (e: IOException) {
            Log.i(TAG, "Stream disconnected: $clientName (${e.message})")
        } finally {
            onDisconnect()
            callback.onStatus("Disconnected: $clientName")
        }
    }

    private fun handleRtsp(req: String, out: OutputStream, clientName: String) {
        val lines = req.split("\r\n")
        var cseq = "1"
        for (line in lines) {
            if (line.startsWith("CSeq:", ignoreCase = true)) {
                cseq = line.substring(5).trim()
            }
        }
        val firstLine = lines.firstOrNull() ?: ""
        val proto = if (firstLine.contains("DMSDP/1.0")) "DMSDP/1.0" else "RTSP/1.0"
        val resp = when {
            firstLine.startsWith("OPTIONS") -> {
                "$proto 200 OK\r\n" +
                "CSeq: $cseq\r\n" +
                "Public: org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER, OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n" +
                "CryptoVer: 1\r\n" +
                "CryptoAbility: 222\r\n" +
                "CryptoAlg: aes128-ctr\r\n" +
                "UnpackAssembly: 90\r\n" +
                "CompressFlag: 165\r\n\r\n"
            }
            firstLine.startsWith("DESCRIBE") -> {
                val sdp = "v=0\r\no=- 0 0 IN IP4 192.168.49.1\r\ns=HiCar\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
                "$proto 200 OK\r\nCSeq: $cseq\r\nContent-Type: application/sdp\r\nContent-Length: ${sdp.length}\r\n\r\n$sdp"
            }
            firstLine.startsWith("SETUP") -> {
                val clientPort = Regex("client_port=(\\d+)-?(\\d*)").find(req)?.value ?: "client_port=50000-50001"
                "$proto 200 OK\r\nCSeq: $cseq\r\nSession: 12345678;timeout=60\r\nTransport: RTP/AVP/UDP;unicast;$clientPort;server_port=50000-50001\r\n\r\n"
            }
            firstLine.startsWith("PLAY") -> {
                "$proto 200 OK\r\nCSeq: $cseq\r\nSession: 12345678\r\nRange: npt=0.000-\r\n\r\n"
            }
            firstLine.startsWith("TEARDOWN") -> {
                "$proto 200 OK\r\nCSeq: $cseq\r\nSession: 12345678\r\n\r\n"
            }
            firstLine.startsWith("GET_PARAMETER") -> {
                "$proto 200 OK\r\nCSeq: $cseq\r\n\r\n"
            }
            firstLine.startsWith("SET_PARAMETER") -> {
                "$proto 200 OK\r\nCSeq: $cseq\r\n\r\n"
            }
            firstLine.contains("200 OK") -> {
                // Phone replied 200 OK to our trigger! Send OPTIONS request if needed
                Log.i(TAG, "RX $proto 200 OK (CSeq=$cseq) from $clientName")
                callback.onStatus("RX $proto 200 OK")
                // Now send OPTIONS request to phone
                val optReq = "$proto OPTIONS * $proto\r\nCSeq: 2\r\n\r\n"
                out.write(optReq.toByteArray(StandardCharsets.UTF_8))
                out.flush()
                Log.i(TAG, "TX OPTIONS request to $clientName:\n$optReq")
                return
            }
            else -> {
                "$proto 200 OK\r\nCSeq: $cseq\r\n\r\n"
            }
        }
        out.write(resp.toByteArray(StandardCharsets.UTF_8))
        out.flush()
        Log.i(TAG, "TX $proto response to $clientName:\n$resp")
        callback.onStatus("TX $proto response (CSeq=$cseq)")
    }

    private fun encodeVarint(v: Int): ByteArray {
        var value = v
        val buf = ByteArray(4)
        var count = 0
        while (count < 4) {
            buf[count] = (value and 0x7F).toByte()
            value = value ushr 7
            if (value == 0) {
                buf[count] = (buf[count].toInt() or 0x80).toByte()
                count++
                break
            }
            count++
        }
        return buf.copyOf(count)
    }

    private fun tlv(tag: Int, value: ByteArray?): ByteArray {
        val tagBytes = encodeVarint(tag)
        if (value == null) {
            return tagBytes + byteArrayOf(0x80.toByte())
        }
        val lenBytes = encodeVarint(value.size)
        return tagBytes + lenBytes + value
    }

    private fun crc16(data: ByteArray, len: Int): Int {
        var crc = 0
        for (i in 0 until len) {
            crc = CRC_TABLE[(crc xor (data[i].toInt() and 0xFF)) and 0xFF] xor (crc ushr 8)
        }
        return crc
    }

    private fun packageCcmp(module: Int, encryptFlag: Int, payload: ByteArray): ByteArray {
        val modBytes = encodeVarint(module)
        val encBytes = tlv(encryptFlag, null)
        val lenBytes = encodeVarint(payload.size)

        val totalLen = 1 + modBytes.size + encBytes.size + lenBytes.size + payload.size + 2
        val out = ByteArray(totalLen)
        out[0] = 0x7F.toByte()
        var offset = 1

        System.arraycopy(modBytes, 0, out, offset, modBytes.size)
        offset += modBytes.size

        System.arraycopy(encBytes, 0, out, offset, encBytes.size)
        offset += encBytes.size

        System.arraycopy(lenBytes, 0, out, offset, lenBytes.size)
        offset += lenBytes.size

        System.arraycopy(payload, 0, out, offset, payload.size)
        offset += payload.size

        val crc = crc16(out, offset)
        out[offset] = (crc and 0xFF).toByte()
        out[offset + 1] = ((crc ushr 8) and 0xFF).toByte()

        return out
    }

    private val D1 = Base64.decode("AnIqp+OQ+x5omVY49B1a1w==", Base64.DEFAULT)
    private val D2 = Base64.decode("V/a52QXvI4ujFDi+rSKiSA==", Base64.DEFAULT)
    private val D3 = Base64.decode("NMfQ0a8IIxBpA6bascMDnQ==", Base64.DEFAULT)

    private fun getNearbyRootKey(): ByteArray {
        val bArr4 = ByteArray(D1.size)
        System.arraycopy(D1, 3, bArr4, 0, D1.size - 3)
        System.arraycopy(D1, 0, bArr4, D1.size - 3, 3)
        val m = xorBytes(bArr4, D2)
        val bArr5 = ByteArray(m.size)
        System.arraycopy(m, 0, bArr5, 5, m.size - 5)
        System.arraycopy(m, m.size - 5, bArr5, 0, 5)
        return xorBytes(bArr5, D3)
    }

    private fun xorBytes(b1: ByteArray, b2: ByteArray): ByteArray {
        val min = Math.min(b1.size, b2.size)
        val res = ByteArray(Math.max(b1.size, b2.size))
        for (i in 0 until min) {
            res[i] = (b1[i].toInt() xor b2[i].toInt()).toByte()
        }
        if (min < b1.size) System.arraycopy(b1, min, res, min, b1.size - min)
        else System.arraycopy(b2, min, res, min, b2.size - min)
        return res
    }

    private fun nearbyCfbCrypt(data: ByteArray, ivSeed: ByteArray, isEncrypt: Boolean): ByteArray {
        val m2 = getNearbyRootKey()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(m2, "HmacSHA256"))
        val a2 = mac.doFinal(ivSeed)
        val key = a2.copyOfRange(0, 16)
        val iv = a2.copyOfRange(16, 32)
        val cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(if (isEncrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    private fun packageCcmpEncrypted(module: Int, cipher: ByteArray, ivSeed: ByteArray): ByteArray {
        val modBytes = encodeVarint(module)
        val innerTlv = tlv(1, ivSeed)
        val encTlv = tlv(1, innerTlv)
        val lenBytes = encodeVarint(cipher.size)

        val totalLen = 1 + modBytes.size + encTlv.size + lenBytes.size + cipher.size + 2
        val out = ByteArray(totalLen)
        out[0] = 0x7F.toByte()
        var offset = 1

        System.arraycopy(modBytes, 0, out, offset, modBytes.size)
        offset += modBytes.size

        System.arraycopy(encTlv, 0, out, offset, encTlv.size)
        offset += encTlv.size

        System.arraycopy(lenBytes, 0, out, offset, lenBytes.size)
        offset += lenBytes.size

        System.arraycopy(cipher, 0, out, offset, cipher.size)
        offset += cipher.size

        val crc = crc16(out, offset)
        out[offset] = (crc and 0xFF).toByte()
        out[offset + 1] = ((crc ushr 8) and 0xFF).toByte()

        return out
    }

    private fun decodeHuaweiVarint(bArr: ByteArray, offset: Int): Pair<Int, Int> {
        var value = 0
        var shift = 0
        var i = offset
        while (i < bArr.size && shift < 32) {
            val b = bArr[i].toInt()
            value = value or ((b and 0x7F) shl shift)
            i++
            shift += 7
            if ((b and 0x80) != 0) {
                return Pair(value, i)
            }
        }
        return Pair(value, i)
    }

    private fun handleModule4Frame(data: ByteArray, out: OutputStream, clientName: String) {
        try {
            // Frame structure:
            // data[0] = 0x7F
            // data[1] = 0x84 (module 4)
            val encTag = decodeHuaweiVarint(data, 2)
            val encLen = decodeHuaweiVarint(data, encTag.second)
            val encTlvDataStart = encLen.second
            val encTlvDataEnd = encTlvDataStart + encLen.first

            val ivTag = decodeHuaweiVarint(data, encTlvDataStart)
            val ivLen = decodeHuaweiVarint(data, ivTag.second)
            val ivStart = ivLen.second
            val ivSeed = data.copyOfRange(ivStart, ivStart + ivLen.first)

            val cipherLenVar = decodeHuaweiVarint(data, encTlvDataEnd)
            val cipherStart = cipherLenVar.second
            val cipherLen = cipherLenVar.first
            val ciphertext = data.copyOfRange(cipherStart, cipherStart + cipherLen)

            Log.i(TAG, "RX Module 4 Encrypted: encType=${encTag.first}, ivSeed=${toHex(ivSeed)}, cipherLen=$cipherLen")

            val plaintext = nearbyCfbCrypt(ciphertext, ivSeed, isEncrypt = false)
            Log.i(TAG, "🔓 Decrypted Module 4 Plaintext: ${toHex(plaintext)}")
            callback.onStatus("RX Module 4 Plaintext (${plaintext.size}B)")

            val cmdTag = decodeHuaweiVarint(plaintext, 0)
            val cmdLen = decodeHuaweiVarint(plaintext, cmdTag.second)
            val cmdPayload = plaintext.copyOfRange(cmdLen.second, cmdLen.second + cmdLen.first)
            Log.i(TAG, "Module 4 Command: ${cmdTag.first}, len: ${cmdLen.first}, payload: ${toHex(cmdPayload)}")

            if (cmdTag.first == 1) { // CMD_DATA_CHANNEL_NEGOTIATION_REQ
                callback.onStatus("RX Module 4 NEGOTIATION_REQ! Sending RESP (GO, 5180MHz)...")
                // Channel 3 (P2P), Role = 1 (GO), Freq = 5180 (Channel 36)
                // Format: bArr = 83 81 83 85 01 3c a8 83 80
                val respA2 = fromHex("83818385013ca88380")
                val tlv2 = tlv(2, respA2)

                val respIv = ByteArray(8).apply { SecureRandom().nextBytes(this) }
                val encryptedCipher = nearbyCfbCrypt(tlv2, respIv, isEncrypt = true)
                val respPacket = packageCcmpEncrypted(4, encryptedCipher, respIv)

                out.write(respPacket)
                out.flush()
                Log.i(TAG, "TX Module 4 NEGOTIATION_RESP: ${toHex(respPacket)}")
                callback.onStatus("🎉 TX Module 4 NEGOTIATION_RESP (GO, 5180MHz) SENT!")
            } else if (cmdTag.first == 7) { // CMD_DATA_CHANNEL_NEGOTIATION_RESULT
                callback.onStatus("🎉 Phone confirmed NEGOTIATION_RESULT (Cmd 7)!")
                Log.i(TAG, "🎉 Phone confirmed NEGOTIATION_RESULT (Cmd 7)!")
                sendModule33GetGcMacReq(out)
            } else if (cmdTag.first == 3) { // CMD_CREATE_DATA_SOCKET_REQ
                callback.onStatus("RX Module 4 CMD_CREATE_DATA_SOCKET_REQ (Cmd 3)!")
                Log.i(TAG, "RX Module 4 CMD_CREATE_DATA_SOCKET_REQ: ${toHex(cmdPayload)}")

                // Respond with CMD_SOCKET_CREATE_RESP (Cmd 4)
                // In Huawei Nearby:
                // Tag 4 payload = status (varint 0) + port (varint 8899) + cmdPayload (channelId, businessId, tag, protocol)
                // When status=0, phone creates TCP socket to (remoteIp, port=8899).
                val statusBytes = encodeVarint(0)
                val portBytes = encodeVarint(8899)
                val respContent = statusBytes + portBytes + cmdPayload
                val tlv4 = tlv(4, respContent)

                val respIv = ByteArray(8).apply { SecureRandom().nextBytes(this) }
                val encryptedCipher = nearbyCfbCrypt(tlv4, respIv, isEncrypt = true)
                val respPacket = packageCcmpEncrypted(4, encryptedCipher, respIv)

                out.write(respPacket)
                out.flush()
                Log.i(TAG, "TX Module 4 CMD_SOCKET_CREATE_RESP (port=8899): ${toHex(respPacket)}")
                callback.onStatus("🎉 TX Module 4 CMD_SOCKET_CREATE_RESP (port=8899) SENT!")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling Module 4 frame: ${e.message}", e)
        }
    }

    private fun handleModule33Frame(data: ByteArray, out: OutputStream, clientName: String) {
        try {
            val encTag = decodeHuaweiVarint(data, 2)
            val encLen = decodeHuaweiVarint(data, encTag.second)
            val encTlvDataStart = encLen.second
            val encTlvDataEnd = encTlvDataStart + encLen.first

            val ivTag = decodeHuaweiVarint(data, encTlvDataStart)
            val ivLen = decodeHuaweiVarint(data, ivTag.second)
            val ivStart = ivLen.second
            val ivSeed = data.copyOfRange(ivStart, ivStart + ivLen.first)

            val cipherLenVar = decodeHuaweiVarint(data, encTlvDataEnd)
            val cipherStart = cipherLenVar.second
            val cipherLen = cipherLenVar.first
            val ciphertext = data.copyOfRange(cipherStart, cipherStart + cipherLen)

            Log.i(TAG, "RX Module 33 Encrypted: ivSeed=${toHex(ivSeed)}, cipherLen=$cipherLen")
            val plaintext = nearbyCfbCrypt(ciphertext, ivSeed, isEncrypt = false)
            Log.i(TAG, "🔓 Decrypted Module 33 Plaintext: ${toHex(plaintext)}")

            val cmdTag = decodeHuaweiVarint(plaintext, 0)
            val cmdLen = decodeHuaweiVarint(plaintext, cmdTag.second)
            val cmdPayload = plaintext.copyOfRange(cmdLen.second, cmdLen.second + cmdLen.first)
            Log.i(TAG, "Module 33 Command: ${cmdTag.first}, len: ${cmdLen.first}, payload: ${toHex(cmdPayload)}")

            if (cmdTag.first == 2) { // CMD_GET_GC_MAC_RESP
                val gcMac = String(cmdPayload, StandardCharsets.UTF_8)
                callback.onStatus("🎉 Phone reported GC MAC: $gcMac")
                Log.i(TAG, "🎉 Phone reported GC MAC: $gcMac")
                sendModule33ReceiveGcInfo(out)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling Module 33 frame: ${e.message}", e)
        }
    }

    private fun sendModule33GetGcMacReq(out: OutputStream) {
        callback.onStatus("TX Module 33 CMD_GET_GC_MAC_REQ...")
        val payload = tlv(1, byteArrayOf())
        val ivSeed = ByteArray(8).apply { SecureRandom().nextBytes(this) }
        val cipher = nearbyCfbCrypt(payload, ivSeed, isEncrypt = true)
        val packet = packageCcmpEncrypted(33, cipher, ivSeed)
        out.write(packet)
        out.flush()
        Log.i(TAG, "TX Module 33 CMD_GET_GC_MAC_REQ: ${toHex(packet)}")
    }

    private fun sendModule33ReceiveGcInfo(out: OutputStream) {
        val gcIp = "192.168.49.2"
        val port = 8899
        val goMac = getP2pMac()
        val gcInfoString = "$gcIp##$p2pSsid\n$goMac\n$p2pPsk\n$p2pFreq##version:3##$port##1##hicarApIp:192.168.49.1"
        Log.i(TAG, "TX Module 33 CMD_RECEIVE_GC_INFO string: $gcInfoString")
        callback.onStatus("TX Module 33 GC_INFO -> SSID: $p2pSsid, BSSID: $goMac")

        val payload = tlv(3, gcInfoString.toByteArray(StandardCharsets.UTF_8))
        val ivSeed = ByteArray(8).apply { SecureRandom().nextBytes(this) }
        val cipher = nearbyCfbCrypt(payload, ivSeed, isEncrypt = true)
        val packet = packageCcmpEncrypted(33, cipher, ivSeed)
        out.write(packet)
        out.flush()
        Log.i(TAG, "TX Module 33 CMD_RECEIVE_GC_INFO packet: ${toHex(packet)}")
        callback.onStatus("🎉 TX Module 33 GC_INFO sent!")
    }

    private val p2pReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION) {
                queryGroupInfo()
            }
        }
    }

    private fun initP2pGroup() {
        try {
            wifiP2pManager = context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
            if (wifiP2pManager == null) {
                Log.e(TAG, "WifiP2pManager not available")
                return
            }
            wifiP2pChannel = wifiP2pManager?.initialize(context, Looper.getMainLooper(), null)

            try {
                val filter = IntentFilter(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
                context.registerReceiver(p2pReceiver, filter)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to register p2pReceiver: ${e.message}")
            }

            // Remove any stale group first, then create autonomous group
            wifiP2pManager?.removeGroup(wifiP2pChannel, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    Log.i(TAG, "Removed previous P2P group, creating fresh group...")
                    createGroupInternal()
                }
                override fun onFailure(reason: Int) {
                    Log.i(TAG, "No previous P2P group to remove ($reason), creating fresh group...")
                    createGroupInternal()
                }
            })
        } catch (e: Exception) {
            Log.e(TAG, "Error initializing P2P group: ${e.message}", e)
        }
    }

    private fun createGroupInternal() {
        val channel = wifiP2pChannel ?: return
        val listener = object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                p2pGroupCreated = true
                Log.i(TAG, "🎉 Wi-Fi P2P Group Owner created successfully!")
                callback.onStatus("🎉 Wi-Fi P2P Group Owner Created!")
                queryGroupInfo()
            }
            override fun onFailure(reason: Int) {
                val msg = when (reason) {
                    WifiP2pManager.BUSY -> "BUSY"
                    WifiP2pManager.P2P_UNSUPPORTED -> "P2P_UNSUPPORTED"
                    else -> "ERROR ($reason)"
                }
                Log.w(TAG, "createGroup failed: $msg, trying legacy createGroup...")
                try {
                    wifiP2pManager?.createGroup(channel, object : WifiP2pManager.ActionListener {
                        override fun onSuccess() {
                            p2pGroupCreated = true
                            Log.i(TAG, "🎉 Legacy Wi-Fi P2P Group Owner created!")
                            callback.onStatus("🎉 Wi-Fi P2P Group Owner Created!")
                            queryGroupInfo()
                        }
                        override fun onFailure(r: Int) {
                            Log.e(TAG, "Legacy createGroup also failed: $r")
                            callback.onStatus("P2P createGroup failed: $r")
                        }
                    })
                } catch (e: SecurityException) {
                    Log.e(TAG, "SecurityException creating P2P group: ${e.message}")
                }
            }
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val config = WifiP2pConfig.Builder()
                    .setNetworkName("DIRECT-HiCar-Pixel")
                    .setPassphrase("12345678")
                    .setGroupOperatingFrequency(5180)
                    .build()
                wifiP2pManager?.createGroup(channel, config, listener)
                return
            }
        } catch (e: Exception) {
            Log.w(TAG, "WifiP2pConfig.Builder failed: ${e.message}")
        }

        try {
            wifiP2pManager?.createGroup(channel, listener)
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException in createGroup: ${e.message}")
        }
    }

    private fun queryGroupInfo() {
        val channel = wifiP2pChannel ?: return
        try {
            wifiP2pManager?.requestGroupInfo(channel) { group ->
                if (group != null) {
                    p2pSsid = group.networkName ?: "DIRECT-fj-Android_4IU5"
                    p2pPsk = group.passphrase ?: "IqNfFAFQ"
                    p2pGoMac = getP2pMac()
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && group.frequency > 0) {
                        p2pFreq = group.frequency
                    } else {
                        p2pFreq = 5745
                    }
                    Log.i(TAG, "P2P Group Info: ssid=$p2pSsid, psk=$p2pPsk, freq=$p2pFreq, goMac=$p2pGoMac")
                    callback.onStatus("P2P Group Ready: $p2pSsid ($p2pFreq MHz, MAC=$p2pGoMac)")
                }
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "requestGroupInfo SecurityException: ${e.message}")
        }
    }

    private fun getP2pMac(): String {
        // Priority 1: Dynamic IPv6 EUI-64 recovery from active p2p interface
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            for (nif in Collections.list(interfaces)) {
                if (!nif.name.lowercase().startsWith("p2p")) continue
                for (addr in Collections.list(nif.inetAddresses)) {
                    if (addr is java.net.Inet6Address && addr.isLinkLocalAddress) {
                        val ipBytes = addr.address
                        if (ipBytes.size == 16) {
                            val b11 = ipBytes[11].toInt() and 0xFF
                            val b12 = ipBytes[12].toInt() and 0xFF
                            if (b11 == 0xFF && b12 == 0xFE) {
                                val macBytes = byteArrayOf(
                                    ((ipBytes[8].toInt() and 0xFF) xor 0x02).toByte(),
                                    ipBytes[9],
                                    ipBytes[10],
                                    ipBytes[13],
                                    ipBytes[14],
                                    ipBytes[15]
                                )
                                val reconstructedMac = macBytes.joinToString(":") { "%02X".format(it) }
                                Log.i(TAG, "Reconstructed P2P MAC from IPv6 EUI-64 on ${nif.name}: $reconstructedMac")
                                return reconstructedMac
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed EUI-64 MAC recovery: ${e.message}")
        }

        // Priority 2: Manual override from p2p_mac.txt
        try {
            val macFile = java.io.File(context.filesDir, "p2p_mac.txt")
            if (macFile.exists()) {
                val fileMac = macFile.readText().trim().uppercase()
                if (fileMac.matches(Regex("([0-9A-F]{2}:){5}[0-9A-F]{2}"))) {
                    Log.i(TAG, "P2P MAC loaded from p2p_mac.txt: $fileMac")
                    return fileMac
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed reading p2p_mac.txt: ${e.message}")
        }

        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            for (nif in Collections.list(interfaces)) {
                val name = nif.name.lowercase()
                val hw = nif.hardwareAddress
                val mac = hw?.joinToString(":") { "%02X".format(it) } ?: "null"
                Log.i(TAG, "Interface ${nif.name} MAC: $mac")
                if (name.startsWith("p2p") && mac != "null" && mac != "02:00:00:00:00:00") {
                    return mac
                }
            }
        } catch (_: Exception) {}
        return "B6:3A:48:CA:63:A3"
    }

    private fun getDeviceSummary(): String {
        val macNoColons = getBluetoothMac().replace(":", "").uppercase()
        val input = (MODEL_ID + macNoColons).toByteArray(StandardCharsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-256").digest(input)
        return digest.joinToString("") { "%02X".format(it) }
    }

    private fun buildCcmpResponse(): ByteArray {
        val summary = getDeviceSummary()
        Log.i(TAG, "buildCcmpResponse summary: $summary")
        val tag2 = tlv(2, byteArrayOf(3.toByte()))
        val tag4 = tlv(4, summary.toByteArray(StandardCharsets.UTF_8))
        val tag6 = tlv(6, byteArrayOf(2.toByte()))
        val payload = tag2 + tag4 + tag6
        return packageCcmp(0, 0, payload)
    }

    private fun buildNegotiationResponse(): ByteArray {
        // Module 2 Tag 4 response:
        // status = 0, port = dataServerPort (channel of NearbyServerSocket / HiCar_RFCOMM)
        // a2: channelId=2, businessId=19, nameLen=8, "Ze****kr", timeout=0
        val bTag = "Ze****kr".toByteArray(StandardCharsets.UTF_8)
        val a2 = byteArrayOf(0x82.toByte(), 0x93.toByte(), (bTag.size or 0x80).toByte()) + bTag + byteArrayOf(0x80.toByte())
        val statusVarint = encodeVarint(0) // status = 0 (SUCCESS)
        val port = if (dataServerPort > 0) dataServerPort else 1
        val portVarint = encodeVarint(port)
        val tag4Value = statusVarint + portVarint + a2
        val tag4 = tlv(4, tag4Value)
        Log.i(TAG, "buildNegotiationResponse with port=$port, bTag=Ze****kr, tag4 size=${tag4.size}: ${toHex(tag4)}")
        return packageCcmp(2, 0, tag4)
    }

    private fun handleIncomingPayload(text: String, out: OutputStream, clientName: String) {
        try {
            // Find JSON objects in stream
            var startIdx = text.indexOf('{')
            while (startIdx >= 0) {
                var braceCount = 0
                var endIdx = -1
                for (i in startIdx until text.length) {
                    if (text[i] == '{') braceCount++
                    else if (text[i] == '}') {
                        braceCount--
                        if (braceCount == 0) {
                            endIdx = i
                            break
                        }
                    }
                }
                if (endIdx < 0) break

                val jsonStr = text.substring(startIdx, endIdx + 1)
                processJsonObject(JSONObject(jsonStr), out, clientName)
                startIdx = text.indexOf('{', endIdx + 1)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error parsing incoming text: ${e.message}")
        }
    }

    private fun processJsonObject(root: JSONObject, out: OutputStream, clientName: String) {
        val operType = root.optInt("oper_type", -1)
        val dataType = root.optInt("dataType", -1)

        if (operType == 1) {
            // Phone requesting capability exchange
            val capData = "{\"CAR_MODE_ID\":\"00049200\",\"CAR_BRAND\":\"Zeekr\",\"DEVICE_TYPE\":\"1\",\"ROM_VERSION\":\"14.2.0.400\",\"CONNECT_ABILITY_KEY\":\"1\",\"MIC_AVAILABLE\":\"1\"}"
            val reply = JSONObject().apply {
                put("version", "14.2.0.400")
                put("oper_type", 1)
                put("data", capData)
                put("usb_connection", false)
                put("is_manual_reconnect", false)
            }.toString().toByteArray(StandardCharsets.UTF_8)
            out.write(reply)
            out.flush()
            callback.onStatus("TX -> $clientName (oper_type=1 ACK)")
            Log.i(TAG, "Replied oper_type=1 ACK")
        } else if (operType == 3) {
            // Phone sending Hichain DeviceAuth passthrough data!
            val rawData = root.optString("data", "")
            val traceId = root.optString("trace_id", "")
            if (rawData.isNotEmpty()) {
                handleHichainAuth(JSONObject(rawData), out, clientName, traceId)
            }
        } else if (dataType == 1 || dataType == 2) {
            // Legacy handshake
            val versionPacket = "{\"dataType\":2,\"dataContent\":\"$VERSION_CONTENT\"}".toByteArray(StandardCharsets.UTF_8)
            out.write(versionPacket)
            out.flush()
        }
    }

    private fun handleHichainAuth(authData: JSONObject, out: OutputStream, clientName: String, traceId: String) {
        val messageCode = authData.optInt("message", -1)
        val payload = authData.optJSONObject("payload") ?: return

        Log.i(TAG, "Hichain DeviceAuth message: $messageCode, payload: $payload")
        callback.onStatus("DeviceAuth MsgCode: $messageCode")

        if (messageCode == 1) {
            // HiChain PAKE DL-SPEKE (Message 1 from Phone)
            val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            val challenge = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            pakeCarSalt = salt
            pakeCarChallenge = challenge

            // Base derivation:
            val pinBytes = PIN_CODE.toByteArray(StandardCharsets.UTF_8)
            val sharedBase = hkdfExtractExpand(salt, pinBytes, "hichain_speke_base_info".toByteArray(StandardCharsets.UTF_8), 32)
            val base = BigInteger(1, sharedBase).modPow(BigInteger.valueOf(2), MODP_P)

            // Keypair generation (28 bytes random private key):
            val privBytes = ByteArray(28).apply { SecureRandom().nextBytes(this) }
            val carPriv = BigInteger(1, privBytes)
            pakeCarPriv = carPriv
            val carEpk = base.modPow(carPriv, MODP_P)
            val carEpkBytes = toFixedByteArray(carEpk, 256)

            // Negotiate DL-SPEKE algorithm (version "2.0.1": bit 0 = 1, DL-SPEKE)
            val versionObj = JSONObject().apply {
                put("currentVersion", "2.0.1")
                put("minVersion", "1.0.0")
            }
            val respPayload = JSONObject().apply {
                put("challenge", toHex(challenge))
                put("salt", toHex(salt))
                put("epk", toHex(carEpkBytes))
                put("version", versionObj)
            }
            val respData = JSONObject().apply {
                put("message", 32769)
                put("payload", respPayload)
            }
            val outerPacket = JSONObject().apply {
                put("version", "14.2.0.400")
                put("oper_type", 3)
                put("data", respData.toString())
                if (traceId.isNotEmpty()) put("trace_id", traceId)
                put("oper_stamp", System.currentTimeMillis())
            }.toString().toByteArray(StandardCharsets.UTF_8)

            out.write(outerPacket)
            out.flush()
            callback.onStatus("TX -> $clientName (PAKE Msg 32769 ServerResponse)")
            Log.i(TAG, "Sent PAKE ServerResponse (32769) to $clientName")

        } else if (messageCode == 2) {
            // Phone sending PAKE ClientConfirm (Message 2)
            val phoneChallengeHex = payload.optString("challenge", "")
            val phoneEpkHex = payload.optString("epk", "")
            val clientProofHex = payload.optString("kcfData", "")

            val phoneChallenge = fromHex(phoneChallengeHex)
            val phoneEpk = fromHex(phoneEpkHex)
            val clientProof = fromHex(clientProofHex)

            pakePhoneChallenge = phoneChallenge

            val salt = pakeCarSalt ?: return
            val carChallenge = pakeCarChallenge ?: return
            val carPriv = pakeCarPriv ?: return

            // Compute shared key:
            val phoneEpkBI = BigInteger(1, phoneEpk)
            val sharedSecret = phoneEpkBI.modPow(carPriv, MODP_P)
            val sharedSecretBytes = toFixedByteArray(sharedSecret, 256)

            // Derive tmpKey (48 bytes):
            val hkdfOut = hkdfExtractExpand(salt, sharedSecretBytes, "hichain_speke_sessionkey_info".toByteArray(StandardCharsets.UTF_8), 48)
            val sKey16 = hkdfOut.copyOfRange(0, 16)
            val sKey32 = hkdfOut.copyOfRange(0, 32)
            sessionKey = sKey32
            pakeSessionKey = sKey16
            val dmsdpKey = hkdfExtractExpand(salt, sKey16, "hichain_return_key".toByteArray(StandardCharsets.UTF_8), 16)
            dmsdpSessionKey = dmsdpKey
            Log.i(TAG, "DMSDP session key derived (16B): ${toHex(dmsdpKey)}")

            // In HwDeviceAuth TaskBase: protected byte[] mSessionKey = new byte[16];
            // In PakeTask generateSessionKey:
            // copyByteArray(tmpKey, 0, mSessionKey, 0, mSessionKey.length = 16);
            // copyByteArray(tmpKey, mSessionKey.length = 16, mKcfKey, 0, 16);
            // mKcfKey is allocated as byte[32] in constructor, so mKcfKey[0..15] = tmpKey[16..31], mKcfKey[16..31] = 0x00.
            val candidateKeys = mapOf(
                "offset16_pad32" to ByteArray(32).apply { System.arraycopy(hkdfOut, 16, this, 0, 16) },
                "offset16_raw16" to hkdfOut.copyOfRange(16, 32),
                "offset16_len32" to hkdfOut.copyOfRange(16, 48),
                "offset32_pad32" to ByteArray(32).apply { System.arraycopy(hkdfOut, 32, this, 0, 16) },
                "offset32_raw16" to hkdfOut.copyOfRange(32, 48)
            )

            val challengeData = concatAll(phoneChallenge, carChallenge)
            var matchedKey: ByteArray? = null
            var matchedName: String? = null

            Log.i(TAG, "PAKE client proof received: ${toHex(clientProof)}")
            for ((name, key) in candidateKeys) {
                val proof = hmacSha256(key, challengeData)
                val ok = clientProof.contentEquals(proof)
                Log.i(TAG, "PAKE candidate $name: ${toHex(proof)} match=$ok")
                if (ok && matchedKey == null) {
                    matchedKey = key
                    matchedName = name
                }
            }

            val isMatch = matchedKey != null
            Log.i(TAG, "PAKE client proof match: $isMatch (matched: $matchedName)")
            callback.onStatus("PAKE Proof Match: $isMatch ($matchedName)")

            if (isMatch) {
                val effectiveKcfKey = matchedKey!!
                // Compute server proof: HMAC(kcfKey, carChallenge + phoneChallenge)
                val serverProof = hmacSha256(effectiveKcfKey, concatAll(carChallenge, phoneChallenge))

                val respPayload = JSONObject().apply {
                    put("kcfData", toHex(serverProof))
                }
                val respData = JSONObject().apply {
                    put("message", 32770)
                    put("payload", respPayload)
                }
                val outerPacket = JSONObject().apply {
                    put("version", "14.2.0.400")
                    put("oper_type", 3)
                    put("data", respData.toString())
                    if (traceId.isNotEmpty()) put("trace_id", traceId)
                    put("oper_stamp", System.currentTimeMillis())
                }.toString().toByteArray(StandardCharsets.UTF_8)

                out.write(outerPacket)
                out.flush()
                val returnKey = hkdfExtractExpand(salt, sKey16, "hichain_return_key".toByteArray(StandardCharsets.UTF_8), 16)
                callback.onStatus("🎉 PIN 123456 AUTHENTICATED! PAKE Session Established!")
                Log.i(TAG, "🎉🎉🎉 PAKE SERVER CONFIRM (32770) SENT! AUTHENTICATION SUCCESSFUL! 🎉🎉🎉")
                Log.i(TAG, "SessionKey(32): ${toHex(sKey32)}, SessionKey(16): ${toHex(sKey16)}, ReturnKey(16): ${toHex(returnKey)}")
            } else {
                Log.e(TAG, "PAKE client proof mismatch!")
            }

        } else if (messageCode == 3) {
            // EXCHANGE_REQUEST (Message 3 from Phone)
            val exAuthInfoHex = payload.optString("exAuthInfo", "")
            val clientExData = fromHex(exAuthInfoHex)

            val sKey16 = pakeSessionKey ?: sessionKey?.copyOfRange(0, 16) ?: return
            val phoneChallenge = pakePhoneChallenge ?: return
            val carChallenge = pakeCarChallenge ?: return

            // Decrypt Phone's exAuthInfo using AES-GCM (AAD = "hichain_exchange_request")
            val peerIv = clientExData.copyOfRange(0, 12)
            val peerCipher = clientExData.copyOfRange(12, clientExData.size)
            val reqAad = "hichain_exchange_request".toByteArray(StandardCharsets.UTF_8)
            val peerPublicKeyInfo = aesGcmDecrypt(sKey16, peerIv, reqAad, peerCipher)
            Log.i(TAG, "Decrypted peerPublicKeyInfo len: ${peerPublicKeyInfo.size}")

            val infoLen = peerPublicKeyInfo.size - 64
            val peerInfoBytes = peerPublicKeyInfo.copyOfRange(0, infoLen)
            val peerSig = peerPublicKeyInfo.copyOfRange(infoLen, peerPublicKeyInfo.size)

            val peerInfoJson = JSONObject(String(peerInfoBytes, StandardCharsets.UTF_8))
            val peerAuthIdHex = peerInfoJson.optString("authId", "")
            val peerAuthPkHex = peerInfoJson.optString("authPk", "")
            Log.i(TAG, "Phone Ed25519 AuthId: $peerAuthIdHex, AuthPk: $peerAuthPkHex")

            // Verify Phone's Ed25519 signature:
            val peerChallenge = concatAll(phoneChallenge, carChallenge)
            val signMsg = sha256(concatAll(peerChallenge, peerInfoBytes))
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(fromHex(peerAuthPkHex), 0))
            verifier.update(signMsg, 0, signMsg.size)
            val isPhoneSigValid = verifier.verifySignature(peerSig)
            Log.i(TAG, "Phone Ed25519 signature valid: $isPhoneSigValid")

            // Generate Car's Ed25519 keypair:
            val kpGen = Ed25519KeyPairGenerator()
            kpGen.init(Ed25519KeyGenerationParameters(SecureRandom()))
            val kp = kpGen.generateKeyPair()
            val carPrivKey = kp.private as Ed25519PrivateKeyParameters
            val carPubKey = kp.public as Ed25519PublicKeyParameters
            val carPubKeyBytes = carPubKey.encoded

            // Prepare Car's PublicKeyInfo JSON:
            val carInfoJson = JSONObject().apply {
                put("authId", toHex(selfId))
                put("authPk", toHex(carPubKeyBytes))
            }
            val carInfoBytes = carInfoJson.toString().toByteArray(StandardCharsets.UTF_8)

            // Sign Car's PublicKeyInfo: Phone expects SHA256(carChallenge + phoneChallenge + carInfoBytes)
            val carPeerChallenge = concatAll(carChallenge, phoneChallenge)
            val carSignMsg = sha256(concatAll(carPeerChallenge, carInfoBytes))
            val signer = Ed25519Signer()
            signer.init(true, carPrivKey)
            signer.update(carSignMsg, 0, carSignMsg.size)
            val carSig = signer.generateSignature()

            val carPlainData = concatAll(carInfoBytes, carSig)

            // Encrypt with AES-GCM (AAD = "hichain_exchange_response"):
            val carIv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
            val respAad = "hichain_exchange_response".toByteArray(StandardCharsets.UTF_8)
            val carCipher = aesGcmEncrypt(sKey16, carIv, respAad, carPlainData)
            val serverExData = concatAll(carIv, carCipher)

            val respPayload = JSONObject().apply {
                put("exAuthInfo", toHex(serverExData))
                put("peerUserType", 1)
            }
            val respData = JSONObject().apply {
                put("message", 32771)
                put("payload", respPayload)
            }
            val outerPacket = JSONObject().apply {
                put("version", "14.2.0.400")
                put("oper_type", 3)
                put("data", respData.toString())
                if (traceId.isNotEmpty()) put("trace_id", traceId)
                put("oper_stamp", System.currentTimeMillis())
            }.toString().toByteArray(StandardCharsets.UTF_8)

            out.write(outerPacket)
            out.flush()
            callback.onStatus("🎉 HICHAIN AUTH 100% COMPLETE! Sent EXCHANGE_RESPONSE (32771)")
            Log.i(TAG, "🎉🎉🎉 HICHAIN AUTH 100% COMPLETE! Sent EXCHANGE_RESPONSE (32771) to $clientName! 🎉🎉🎉")

        } else if (messageCode == 17 || messageCode == 33) {
            // LITE_ISO_REQUEST (33) / AUTH_START_REQUEST (17) from Phone!
            val replyCode = if (messageCode == 17) 32785 else 32801
            val isoSaltHex = payload.optString("isoSalt", "")
            val peerAuthIdHex = payload.optString("peerAuthId", "")
            val seedHex = payload.optString("seed", "")

            peerRandom = fromHex(isoSaltHex)
            peerId = fromHex(peerAuthIdHex)
            val seed = fromHex(seedHex)

            selfRandom = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            val hashedPin = sha256(PIN_CODE.toByteArray(StandardCharsets.UTF_8))
            val derivedPsk = hmacSha256(hashedPin, seed)
            psk = derivedPsk

            val hmacInput = concatAll(selfRandom!!, peerRandom!!, peerId!!, selfId)
            val serverFirstHmac = hmacSha256(derivedPsk, hmacInput)

            val versionObj = JSONObject().apply {
                put("currentVersion", "2.0.16")
                put("minVersion", "1.0.0")
            }
            val respPayload = JSONObject().apply {
                put("isoSalt", toHex(selfRandom!!))
                put("peerAuthId", toHex(selfId))
                put("peerUserType", 1)
                put("token", toHex(serverFirstHmac))
                put("operationCode", 1)
                put("version", versionObj)
            }
            val respData = JSONObject().apply {
                put("message", replyCode)
                put("payload", respPayload)
            }
            val outerPacket = JSONObject().apply {
                put("version", "14.2.0.400")
                put("oper_type", 3)
                put("data", respData.toString())
                if (traceId.isNotEmpty()) put("trace_id", traceId)
                put("oper_stamp", System.currentTimeMillis())
            }.toString().toByteArray(StandardCharsets.UTF_8)

            out.write(outerPacket)
            out.flush()
            callback.onStatus("TX -> $clientName (DeviceAuth Msg $replyCode ServerResponse)")
            Log.i(TAG, "Sent ISO RESPONSE ($replyCode) to $clientName")

        } else if (messageCode == 18 || messageCode == 34) {
            // LITE_ISO_CLIENT_MAC (34) / AUTH_ACK_REQUEST (18) from Phone!
            val replyCode = if (messageCode == 18) 32786 else 32802
            val clientTokenHex = payload.optString("token", "")
            val clientToken = fromHex(clientTokenHex)
            val currentPsk = psk ?: return

            val expectedClientHmac = hmacSha256(currentPsk, concatAll(peerRandom!!, selfRandom!!, selfId, peerId!!))
            val isMatch = clientToken.contentEquals(expectedClientHmac)

            Log.i(TAG, "Client token match: $isMatch")
            callback.onStatus("DeviceAuth Token Match: $isMatch")

            if (isMatch) {
                val isoSessionKey = hkdfExtractExpand(currentPsk, concatAll(peerRandom!!, selfRandom!!), "hichain_iso_session_key".toByteArray(StandardCharsets.UTF_8), 32)
                sessionKey = isoSessionKey
                val sKey16 = isoSessionKey.copyOfRange(0, 16)
                pakeSessionKey = sKey16
                val dmsdpKey = hkdfExtractExpand(peerRandom!!, sKey16, "hichain_return_key".toByteArray(StandardCharsets.UTF_8), 16)
                dmsdpSessionKey = dmsdpKey
                Log.i(TAG, "ISO DMSDP session key derived (16B): ${toHex(dmsdpKey)}")

                val returnCodeMac = hmacSha256(currentPsk, byteArrayOf(0, 0, 0, 0))
                val respPayload = JSONObject().apply {
                    put("returnCodeMac", toHex(returnCodeMac))
                }
                val respData = JSONObject().apply {
                    put("message", replyCode)
                    put("payload", respPayload)
                }
                val outerPacket = JSONObject().apply {
                    put("version", "14.2.0.400")
                    put("oper_type", 3)
                    put("data", respData.toString())
                    if (traceId.isNotEmpty()) put("trace_id", traceId)
                    put("oper_stamp", System.currentTimeMillis())
                }.toString().toByteArray(StandardCharsets.UTF_8)

                out.write(outerPacket)
                out.flush()
                callback.onStatus("🎉 PIN 123456 AUTHENTICATION SUCCESSFUL! Session established.")
                Log.i(TAG, "Sent ISO SERVER DERIVE ($replyCode). AUTHENTICATION COMPLETE!")
            }
        }
    }

    private fun toFixedByteArray(bi: BigInteger, length: Int): ByteArray {
        val raw = bi.toByteArray()
        val result = ByteArray(length)
        if (raw.size > length) {
            System.arraycopy(raw, raw.size - length, result, 0, length)
        } else {
            System.arraycopy(raw, 0, result, length - raw.size, raw.size)
        }
        return result
    }

    private fun hkdfExtractExpand(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int = 32): ByteArray {
        val prkMac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(salt, "HmacSHA256")) }
        val prk = prkMac.doFinal(ikm)
        val expandMac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(prk, "HmacSHA256")) }

        val result = ByteArray(length)
        var t = ByteArray(0)
        var generated = 0
        var counter: Byte = 1

        while (generated < length) {
            expandMac.reset()
            if (t.isNotEmpty()) {
                expandMac.update(t)
            }
            expandMac.update(info)
            expandMac.update(counter)
            t = expandMac.doFinal()
            val toCopy = Math.min(t.size, length - generated)
            System.arraycopy(t, 0, result, generated, toCopy)
            generated += toCopy
            counter++
        }
        return result
    }

    private fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertextWithTag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertextWithTag)
    }

    private fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun concatAll(vararg arrays: ByteArray): ByteArray {
        var totalLen = 0
        for (a in arrays) totalLen += a.size
        val result = ByteArray(totalLen)
        var offset = 0
        for (a in arrays) {
            System.arraycopy(a, 0, result, offset, a.size)
            offset += a.size
        }
        return result
    }

    private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun fromHex(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    private fun buildEncryptedPayload(): ByteArray {
        val macAddress = getBluetoothMac()
        val macParts = macAddress.split(":").map { it.toInt(16).toByte() }.toByteArray()
        val b64Default = Base64.encode(macParts, Base64.DEFAULT) // 9 bytes: [49,68,111,115,105,73,88,79,10]
        val macArrayJson = b64Default.joinToString(separator = ",", prefix = "[", postfix = "]") { it.toString() }

        val json = "{\"macBytes\":$macArrayJson,\"modelId\":\"$MODEL_ID\"}"
        Log.i(TAG, "Plain CarDeviceInfo: $json")

        return try {
            val keyBytes = AES_KEY.toByteArray(StandardCharsets.UTF_8)
            val ivBytes = ByteArray(16)
            val modelIdBytes = MODEL_ID.toByteArray(StandardCharsets.UTF_8)
            System.arraycopy(modelIdBytes, 0, ivBytes, 0, minOf(modelIdBytes.size, 16))

            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val secretKey = SecretKeySpec(keyBytes, "AES")
            val ivSpec = IvParameterSpec(ivBytes)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)

            val encrypted = cipher.doFinal(json.toByteArray(StandardCharsets.UTF_8))
            Base64.encode(encrypted, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Encryption failed: ${e.message}", e)
            ByteArray(0)
        }
    }

    private fun getBluetoothMac(): String {
        return try {
            android.provider.Settings.Secure.getString(context.contentResolver, "bluetooth_address") ?: "D4:3A:2C:88:85:CE"
        } catch (e: Exception) {
            "D4:3A:2C:88:85:CE"
        }
    }
}
