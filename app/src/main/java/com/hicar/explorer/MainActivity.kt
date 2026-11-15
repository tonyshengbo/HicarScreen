package com.hicar.explorer

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import android.widget.Button
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    // UI
    private lateinit var tvBleStatus: TextView
    private lateinit var tvBleDetail: TextView
    private lateinit var btnBleToggle: Button
    private lateinit var tvWifiStatus: TextView
    private lateinit var tvWifiDetail: TextView
    private lateinit var btnWifiDiscover: Button
    private lateinit var tvMdnsStatus: TextView
    private lateinit var tvMdnsDetail: TextView
    private lateinit var tvTcpStatus: TextView
    private lateinit var tvTcpDetail: TextView
    private lateinit var tvLog: TextView
    private lateinit var scrollLog: ScrollView
    private lateinit var btnCopyLog: Button
    private lateinit var btnClearLog: Button
    private lateinit var btnStartAll: Button
    private lateinit var btnClickAgree: Button

    // Managers
    private lateinit var bleAdvertiser: BleAdvertiser
    private lateinit var hiCarServer: HiCarServer
    private lateinit var hiCarBtServer: HiCarBtServer
    private lateinit var wifiDirectManager: WifiDirectManager

    private val mainHandler = Handler(Looper.getMainLooper())
    private var isAdvertising = false

    companion object {
        private const val PERM_REQUEST_CODE = 100
    }

    private val requiredPermissions: Array<String>
        get() {
            val perms = mutableListOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,
                Manifest.permission.ACCESS_WIFI_STATE,
                Manifest.permission.CHANGE_WIFI_STATE,
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                perms.add(Manifest.permission.BLUETOOTH_ADVERTISE)
                perms.add(Manifest.permission.BLUETOOTH_CONNECT)
                perms.add(Manifest.permission.BLUETOOTH_SCAN)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                perms.add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
            return perms.toTypedArray()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        setContentView(R.layout.activity_main)

        initViews()
        initManagers()
        initSurfaceView()
        checkAndRequestPermissions()
    }

    @android.annotation.SuppressLint("ClickableViewAccessibility")
    private fun initSurfaceView() {
        val surfaceView = findViewById<SurfaceView>(R.id.surface_view)
        surfaceView.holder.addCallback(object : SurfaceHolder.Callback {
            override fun surfaceCreated(holder: SurfaceHolder) {
                appendLog("[SURFACE] Surface created, binding to video decoder")
                hiCarServer.setSurface(holder.surface)
            }

            override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
                appendLog("[SURFACE] Surface changed: ${width}x${height}")
                hiCarServer.setSurface(holder.surface)
            }

            override fun surfaceDestroyed(holder: SurfaceHolder) {
                appendLog("[SURFACE] Surface destroyed")
                hiCarServer.setSurface(null)
            }
        })

        // Capture touch events directly on the SurfaceView and forward to HiCar virtual display
        surfaceView.setOnTouchListener { v, event ->
            v.parent?.requestDisallowInterceptTouchEvent(true)
            val w = v.width.toFloat()
            val h = v.height.toFloat()
            if (w <= 0f || h <= 0f) return@setOnTouchListener false

            fun getPointers(excludeIndex: Int = -1): List<HiCarServer.TouchPointer> {
                val list = ArrayList<HiCarServer.TouchPointer>()
                for (i in 0 until event.pointerCount) {
                    if (i == excludeIndex) continue
                    val pid = event.getPointerId(i)
                    val px = ((event.getX(i) / w) * 1920f).toInt().coerceIn(0, 1920)
                    val py = ((event.getY(i) / h) * 1080f).toInt().coerceIn(0, 1080)
                    list.add(HiCarServer.TouchPointer(pid, px, py))
                }
                return list
            }

            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    val pointers = getPointers()
                    hiCarServer.sendTouchEvents(0, pointers)
                    appendLog("👆 Touch DOWN: (${pointers[0].x}, ${pointers[0].y})")
                }
                MotionEvent.ACTION_POINTER_DOWN -> {
                    val pointers = getPointers()
                    hiCarServer.sendTouchEvents(0, pointers)
                    appendLog("✌️ Multi-touch DOWN: ${pointers.size} fingers")
                }
                MotionEvent.ACTION_MOVE -> {
                    val pointers = getPointers()
                    hiCarServer.sendTouchEvents(2, pointers)
                }
                MotionEvent.ACTION_POINTER_UP -> {
                    val upIndex = event.actionIndex
                    val remaining = getPointers(excludeIndex = upIndex)
                    if (remaining.isNotEmpty()) {
                        hiCarServer.sendTouchEvents(2, remaining)
                    }
                    appendLog("✌️ Multi-touch UP: remaining ${remaining.size} fingers")
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    val pointers = getPointers()
                    hiCarServer.sendTouchEvents(1, pointers)
                    if (pointers.isNotEmpty()) {
                        appendLog("👆 Touch UP: (${pointers[0].x}, ${pointers[0].y})")
                    }
                }
            }
            true
        }
    }

    private fun initViews() {
        tvBleStatus = findViewById(R.id.tv_ble_status)
        tvBleDetail = findViewById(R.id.tv_ble_detail)
        btnBleToggle = findViewById(R.id.btn_ble_toggle)
        tvWifiStatus = findViewById(R.id.tv_wifi_status)
        tvWifiDetail = findViewById(R.id.tv_wifi_detail)
        btnWifiDiscover = findViewById(R.id.btn_wifi_discover)
        tvMdnsStatus = findViewById(R.id.tv_mdns_status)
        tvMdnsDetail = findViewById(R.id.tv_mdns_detail)
        tvTcpStatus = findViewById(R.id.tv_tcp_status)
        tvTcpDetail = findViewById(R.id.tv_tcp_detail)
        tvLog = findViewById(R.id.tv_log)
        scrollLog = findViewById(R.id.scroll_log)
        btnCopyLog = findViewById(R.id.btn_copy_log)
        btnClearLog = findViewById(R.id.btn_clear_log)
        btnStartAll = findViewById(R.id.btn_start_all)
        btnClickAgree = findViewById(R.id.btn_click_agree)

        btnBleToggle.setOnClickListener { toggleBle() }
        btnWifiDiscover.setOnClickListener { startWifiDirect() }
        btnCopyLog.setOnClickListener { copyLog() }
        btnClearLog.setOnClickListener { clearLog() }
        btnStartAll.setOnClickListener { startAllServices() }
        btnClickAgree.setOnClickListener {
            appendLog("👆 Auto-agreeing: checking box at (150, 928) then confirming at (643, 1012)...")
            // Step 1: Click the checkbox "我已阅读并同意本声明"
            hiCarServer.sendClick(150, 928)
            // Step 2: Click "确认" button
            window.decorView.postDelayed({
                hiCarServer.sendClick(643, 1012)
            }, 300)
        }
    }

    private fun initManagers() {
        bleAdvertiser = BleAdvertiser(this, object : BleAdvertiser.Callback {
            override fun onStatusChanged(advertising: Boolean, detail: String) {
                mainHandler.post {
                    isAdvertising = advertising
                    tvBleStatus.text = if (advertising) "ON" else "OFF"
                    tvBleStatus.setTextColor(
                        if (advertising) 0xFF03DAC5.toInt() else 0xFFCF6679.toInt()
                    )
                    tvBleDetail.text = detail
                    btnBleToggle.text = if (advertising) "Stop BLE Advertising" else "Start BLE Advertising"
                    appendLog("[BLE] $detail")
                }
            }
        })

        hiCarBtServer = HiCarBtServer(this, object : HiCarBtServer.Callback {
            override fun onStatus(detail: String) {
                mainHandler.post {
                    appendLog("[BT-SERVER] $detail")
                }
            }

            override fun onRfcommData(source: String, data: ByteArray) {
                mainHandler.post {
                    appendLog("[RX from $source] ${data.size} bytes\n${formatHexDump(data)}")
                }
            }
        })

        hiCarServer = HiCarServer(this, hiCarBtServer, object : HiCarServer.Callback {
            override fun onMdnsStatusChanged(registered: Boolean, detail: String) {
                mainHandler.post {
                    tvMdnsStatus.text = if (registered) "Registered" else "Inactive"
                    tvMdnsStatus.setTextColor(
                        if (registered) 0xFF03DAC5.toInt() else 0xFF888888.toInt()
                    )
                    tvMdnsDetail.text = detail
                    appendLog("[mDNS] $detail")
                }
            }

            override fun onTcpStatusChanged(running: Boolean, detail: String) {
                mainHandler.post {
                    tvTcpStatus.text = if (running) "Listening" else "Stopped"
                    tvTcpStatus.setTextColor(
                        if (running) 0xFF03DAC5.toInt() else 0xFF888888.toInt()
                    )
                    tvTcpDetail.text = detail
                    appendLog("[TCP] $detail")
                }
            }

            override fun onDataReceived(clientInfo: String, data: ByteArray) {
                mainHandler.post {
                    val hex = formatHexDump(data)
                    appendLog("[RX from $clientInfo]\n$hex")
                }
            }
        })

        wifiDirectManager = WifiDirectManager(this, object : WifiDirectManager.Callback {
            override fun onStatusChanged(status: String) {
                mainHandler.post {
                    tvWifiStatus.text = status
                    val isConnected = status.contains("Connected", ignoreCase = true)
                    tvWifiStatus.setTextColor(
                        if (isConnected) 0xFF03DAC5.toInt() else 0xFF888888.toInt()
                    )
                    appendLog("[WiFi-P2P] $status")
                }
            }

            override fun onDetailChanged(detail: String) {
                mainHandler.post {
                    tvWifiDetail.text = detail
                }
            }
        })
    }

    private fun toggleBle() {
        if (!isAdvertising) {
            bleAdvertiser.startAdvertising()
        } else {
            bleAdvertiser.stopAdvertising()
        }
    }

    private fun startWifiDirect() {
        wifiDirectManager.startDiscovery()
        btnWifiDiscover.text = "P2P Active"
        btnWifiDiscover.isEnabled = false
    }

    private fun startAllServices() {
        val bm = getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = bm?.adapter
        if (adapter != null && adapter.scanMode != BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE) {
            try {
                val discoverableIntent = android.content.Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).apply {
                    putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 3600)
                }
                startActivity(discoverableIntent)
            } catch (e: Exception) {
                appendLog("[WARN] Cannot request discoverable: ${e.message}")
            }
        }

        bleAdvertiser.startAdvertising()
        hiCarBtServer.start()
        hiCarServer.start()
        // wifiDirectManager.startDiscovery() // P2P Group Owner is managed by HiCarBtServer
        btnStartAll.text = "✓ All Services Running"
        btnStartAll.isEnabled = false
        appendLog("[SYSTEM] All services started (BLE + GATT + RFCOMM + mDNS + TCP)")
    }

    private fun copyLog() {
        val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val clip = android.content.ClipData.newPlainText("HiCar Log", tvLog.text.toString())
        cm.setPrimaryClip(clip)
        Toast.makeText(this, "Log copied to clipboard", Toast.LENGTH_SHORT).show()
    }

    private fun clearLog() {
        tvLog.text = "[Log cleared]\n"
    }

    private fun appendLog(text: String) {
        val ts = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US)
            .format(java.util.Date())
        tvLog.append("[$ts] $text\n")
        scrollLog.post { scrollLog.fullScroll(View.FOCUS_DOWN) }
    }

    private fun formatHexDump(data: ByteArray): String {
        if (data.isEmpty()) return "(empty)"
        val sb = StringBuilder()
        var offset = 0
        while (offset < data.size) {
            val lineLen = minOf(16, data.size - offset)
            sb.append(String.format("%04X  ", offset))
            for (i in 0 until 16) {
                if (i < lineLen) {
                    sb.append(String.format("%02X ", data[offset + i]))
                } else {
                    sb.append("   ")
                }
                if (i == 7) sb.append(" ")
            }
            sb.append(" |")
            for (i in 0 until lineLen) {
                val b = data[offset + i].toInt() and 0xFF
                sb.append(if (b in 32..126) b.toChar() else '.')
            }
            sb.append("|\n")
            offset += lineLen
        }
        return sb.toString()
    }

    private fun checkAndRequestPermissions() {
        val missing = requiredPermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            onPermissionsGranted()
        } else {
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), PERM_REQUEST_CODE)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERM_REQUEST_CODE) {
            val denied = permissions.zip(grantResults.toList())
                .filter { it.second != PackageManager.PERMISSION_GRANTED }
                .map { it.first.substringAfterLast('.') }
            if (denied.isEmpty()) {
                onPermissionsGranted()
            } else {
                Toast.makeText(this, "Denied: ${denied.joinToString()}", Toast.LENGTH_LONG).show()
                appendLog("[WARN] Denied permissions: ${denied.joinToString()}")
            }
        }
    }

    private fun onPermissionsGranted() {
        appendLog("[SYSTEM] Permissions OK – starting services automatically")
        startAllServices()
    }

    override fun onDestroy() {
        super.onDestroy()
        bleAdvertiser.stopAdvertising()
        hiCarBtServer.stop()
        hiCarServer.stop()
        wifiDirectManager.stop()
    }
}
