package com.hicar.explorer

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.RelativeLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "HiCarReceiver"
        private const val PERM_REQUEST_CODE = 100
    }

    // UI - Main Automotive Layers
    private lateinit var surfaceView: SurfaceView
    private lateinit var layoutStandby: RelativeLayout
    private lateinit var tvStatusBadge: TextView
    private lateinit var tvHeadline: TextView
    private lateinit var tvInstructions: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var tvDeviceName: TextView

    // Footer Indicators
    private lateinit var tvFooterBle: TextView
    private lateinit var tvFooterWifi: TextView
    private lateinit var tvFooterAudio: TextView

    // Debug Diagnostics Overlay
    private lateinit var layoutDebugOverlay: RelativeLayout
    private lateinit var btnToggleDebug: TextView
    private lateinit var btnCloseDebug: Button
    private lateinit var btnCopyLog: Button
    private lateinit var btnClearLog: Button
    private lateinit var tvLog: TextView
    private lateinit var scrollLog: ScrollView

    // Protocol Managers
    private lateinit var bleAdvertiser: BleAdvertiser
    private lateinit var hiCarServer: HiCarServer
    private lateinit var hiCarBtServer: HiCarBtServer
    private lateinit var wifiDirectManager: WifiDirectManager

    private val mainHandler = Handler(Looper.getMainLooper())
    private val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    private var isProjecting = false

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
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        setContentView(R.layout.activity_main)

        initViews()
        initManagers()
        initSurfaceView()
        checkAndRequestPermissions()
    }

    private fun initViews() {
        surfaceView = findViewById(R.id.surface_view)
        layoutStandby = findViewById(R.id.layout_standby)
        tvStatusBadge = findViewById(R.id.tv_status_badge)
        tvHeadline = findViewById(R.id.tv_headline)
        tvInstructions = findViewById(R.id.tv_instructions)
        tvStatusDetail = findViewById(R.id.tv_status_detail)
        tvDeviceName = findViewById(R.id.tv_device_name)

        tvFooterBle = findViewById(R.id.tv_footer_ble)
        tvFooterWifi = findViewById(R.id.tv_footer_wifi)
        tvFooterAudio = findViewById(R.id.tv_footer_audio)

        layoutDebugOverlay = findViewById(R.id.layout_debug_overlay)
        btnToggleDebug = findViewById(R.id.btn_toggle_debug)
        btnCloseDebug = findViewById(R.id.btn_close_debug)
        btnCopyLog = findViewById(R.id.btn_copy_log)
        btnClearLog = findViewById(R.id.btn_clear_log)
        tvLog = findViewById(R.id.tv_log)
        scrollLog = findViewById(R.id.scroll_log)

        // Debug toggle listeners
        btnToggleDebug.setOnClickListener {
            val isVisible = layoutDebugOverlay.visibility == View.VISIBLE
            layoutDebugOverlay.visibility = if (isVisible) View.GONE else View.VISIBLE
        }
        btnCloseDebug.setOnClickListener {
            layoutDebugOverlay.visibility = View.GONE
        }
        btnCopyLog.setOnClickListener {
            val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("HiCar Log", tvLog.text.toString()))
            Toast.makeText(this, "日志已复制到剪贴板", Toast.LENGTH_SHORT).show()
        }
        btnClearLog.setOnClickListener {
            tvLog.text = ""
        }

        // Display current Bluetooth device name
        val bm = getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val btName = bm?.adapter?.name ?: "HiCar"
        tvDeviceName.text = "车载设备: $btName (蓝牙可见)"
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun initSurfaceView() {
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

        // Capture multi-touch events directly on SurfaceView and forward via UIBC
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
                }
                MotionEvent.ACTION_POINTER_DOWN -> {
                    val pointers = getPointers()
                    hiCarServer.sendTouchEvents(0, pointers)
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
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    val pointers = getPointers()
                    hiCarServer.sendTouchEvents(1, pointers)
                }
            }
            true
        }
    }

    private fun initManagers() {
        bleAdvertiser = BleAdvertiser(this, object : BleAdvertiser.Callback {
            override fun onStatusChanged(advertising: Boolean, detail: String) {
                mainHandler.post {
                    tvFooterBle.text = if (advertising) "BLE 广播: 开启" else "BLE 广播: 未开启"
                    tvFooterBle.setTextColor(if (advertising) 0xFF30D158.toInt() else 0xFF8A94A6.toInt())
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
                    appendLog("[RX from $source] ${data.size} bytes")
                }
            }
        })

        hiCarServer = HiCarServer(this, hiCarBtServer, object : HiCarServer.Callback {
            override fun onStateChanged(state: HiCarServer.ConnectionState, detail: String) {
                mainHandler.post {
                    updateConnectionState(state, detail)
                }
            }

            override fun onMdnsStatusChanged(registered: Boolean, detail: String) {
                mainHandler.post {
                    appendLog("[mDNS] $detail")
                }
            }

            override fun onTcpStatusChanged(running: Boolean, detail: String) {
                mainHandler.post {
                    appendLog("[TCP] $detail")
                }
            }

            override fun onDataReceived(clientInfo: String, data: ByteArray) {
                mainHandler.post {
                    appendLog("[RX from $clientInfo] ${data.size} bytes")
                }
            }
        })

        wifiDirectManager = WifiDirectManager(this, object : WifiDirectManager.Callback {
            override fun onStatusChanged(status: String) {
                mainHandler.post {
                    val isConnected = status.contains("Connected", ignoreCase = true)
                    tvFooterWifi.text = if (isConnected) "Wi-Fi 直连: 已连接" else "Wi-Fi P2P-GO: 就绪"
                    tvFooterWifi.setTextColor(if (isConnected) 0xFF0A84FF.toInt() else 0xFF30D158.toInt())
                    appendLog("[WiFi-P2P] $status")
                }
            }

            override fun onDetailChanged(detail: String) {
                mainHandler.post {
                    appendLog("[WiFi-Detail] $detail")
                }
            }
        })
    }

    private fun updateConnectionState(state: HiCarServer.ConnectionState, detail: String) {
        when (state) {
            HiCarServer.ConnectionState.IDLE -> {
                isProjecting = false
                exitImmersiveMode()
                layoutStandby.visibility = View.VISIBLE
                layoutStandby.animate().alpha(1f).setDuration(250).start()
                tvStatusBadge.text = "● 等待华为手机连接"
                tvStatusBadge.setTextColor(0xFF30D158.toInt())
                tvHeadline.text = "请在手机上发起连接"
                tvStatusDetail.text = detail
                appendLog("[STATE] IDLE - $detail")
            }
            HiCarServer.ConnectionState.CONNECTING -> {
                tvStatusBadge.text = "● 正在建立连接"
                tvStatusBadge.setTextColor(0xFFFF9F0A.toInt())
                tvHeadline.text = "手机已接入，正在安全握手..."
                tvStatusDetail.text = detail
                appendLog("[STATE] CONNECTING - $detail")
            }
            HiCarServer.ConnectionState.CONNECTED -> {
                tvStatusBadge.text = "● 认证成功"
                tvStatusBadge.setTextColor(0xFF0A84FF.toInt())
                tvHeadline.text = "握手完成，正在开启投屏通道..."
                tvStatusDetail.text = detail
                appendLog("[STATE] CONNECTED - $detail")
            }
            HiCarServer.ConnectionState.PROJECTING -> {
                if (!isProjecting) {
                    isProjecting = true
                    enterImmersiveMode()
                    layoutStandby.animate()
                        .alpha(0f)
                        .setDuration(350)
                        .withEndAction { layoutStandby.visibility = View.GONE }
                        .start()
                    appendLog("🎉 [STATE] PROJECTING - Fully active and rendering!")
                }
            }
            HiCarServer.ConnectionState.DISCONNECTED -> {
                isProjecting = false
                exitImmersiveMode()
                layoutStandby.visibility = View.VISIBLE
                layoutStandby.animate().alpha(1f).setDuration(250).start()
                tvStatusBadge.text = "● 连接已断开"
                tvStatusBadge.setTextColor(0xFFFF9F0A.toInt())
                tvHeadline.text = "连接已结束，正在等待重新回连..."
                tvStatusDetail.text = detail
                appendLog("[STATE] DISCONNECTED - $detail")
            }
        }
    }

    private fun enterImmersiveMode() {
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility = (
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE
            or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
            or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
            or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
            or View.SYSTEM_UI_FLAG_FULLSCREEN
            or View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
        )
    }

    private fun exitImmersiveMode() {
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && isProjecting) {
            enterImmersiveMode()
        }
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
        appendLog("[SYSTEM] Autonomous wireless receiver engine online")
    }

    private fun appendLog(text: String) {
        val ts = timeFormat.format(Date())
        Log.i(TAG, "[$ts] $text")
        tvLog.append("[$ts] $text\n")
        scrollLog.post { scrollLog.fullScroll(View.FOCUS_DOWN) }
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
        appendLog("[SYSTEM] Permissions OK – starting services")
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
