package com.hicar.explorer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.net.wifi.p2p.WifiP2pManager.ActionListener
import android.net.wifi.p2p.WifiP2pManager.ConnectionInfoListener
import android.os.Looper
import android.util.Log

/**
 * WifiDirectManager – Manages Wi-Fi P2P for HiCar.
 *
 * The Huawei phone will initiate a Wi-Fi Direct connection after BLE pairing.
 * We:
 *  1. Register as a P2P peer
 *  2. Listen for PEERS_CHANGED, CONNECTION_CHANGED, STATE_CHANGED
 *  3. Accept any incoming P2P connection request
 *  4. Report the IP address of the connected group owner (the phone)
 */
class WifiDirectManager(
    private val context: Context,
    private val callback: Callback
) {

    interface Callback {
        fun onStatusChanged(status: String)
        fun onDetailChanged(detail: String)
    }

    companion object {
        private const val TAG = "WifiDirectManager"
    }

    private val manager: WifiP2pManager =
        context.getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
    private val channel: WifiP2pManager.Channel =
        manager.initialize(context, Looper.getMainLooper(), null)

    private val intentFilter = IntentFilter().apply {
        addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
        addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
        addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
    }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                    val state = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, -1)
                    val enabled = state == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                    callback.onStatusChanged(if (enabled) "P2P Enabled" else "P2P Disabled")
                    Log.i(TAG, "P2P state: $state")
                }

                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                    requestPeers()
                }

                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                    val networkInfo = if (android.os.Build.VERSION.SDK_INT >= 29) {
                        intent.getParcelableExtra(
                            WifiP2pManager.EXTRA_NETWORK_INFO,
                            android.net.NetworkInfo::class.java
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO)
                    }

                    if (networkInfo?.isConnected == true) {
                        callback.onStatusChanged("P2P Connected!")
                        manager.requestConnectionInfo(channel, connectionInfoListener)
                    } else {
                        callback.onStatusChanged("P2P Disconnected")
                        callback.onDetailChanged("Waiting for P2P connection...")
                    }
                }

                WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {
                    val device = if (android.os.Build.VERSION.SDK_INT >= 29) {
                        intent.getParcelableExtra(
                            WifiP2pManager.EXTRA_WIFI_P2P_DEVICE,
                            WifiP2pDevice::class.java
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(WifiP2pManager.EXTRA_WIFI_P2P_DEVICE)
                    }
                    device?.let {
                        callback.onDetailChanged(
                            "This device: ${it.deviceName} | ${it.deviceAddress}"
                        )
                        Log.i(TAG, "This device: ${it.deviceName} ${it.deviceAddress}")
                    }
                }
            }
        }
    }

    private val connectionInfoListener = ConnectionInfoListener { info: WifiP2pInfo ->
        val groupOwner = info.groupOwnerAddress?.hostAddress ?: "unknown"
        val isOwner = info.isGroupOwner
        val detail = if (isOwner) {
            "We are Group Owner | Phone IP should connect to us"
        } else {
            "Group Owner (phone): $groupOwner"
        }
        callback.onDetailChanged(detail)
        Log.i(TAG, "P2P info: isOwner=$isOwner, GO=$groupOwner")
    }

    private fun requestPeers() {
        try {
            manager.requestPeers(channel) { peerList ->
                val devices = peerList.deviceList
                if (devices.isEmpty()) {
                    callback.onDetailChanged("No P2P peers found")
                } else {
                    val names = devices.joinToString { it.deviceName }
                    callback.onDetailChanged("Peers: $names")
                    Log.i(TAG, "P2P peers: $names")
                }
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "requestPeers security exception: ${e.message}")
        }
    }

    fun startDiscovery() {
        try {
            context.registerReceiver(receiver, intentFilter)
        } catch (_: Exception) {}

        manager.discoverPeers(channel, object : ActionListener {
            override fun onSuccess() {
                callback.onStatusChanged("P2P Discovery started")
                Log.i(TAG, "P2P discovery started")
            }

            override fun onFailure(reason: Int) {
                val msg = when (reason) {
                    WifiP2pManager.ERROR -> "Error"
                    WifiP2pManager.P2P_UNSUPPORTED -> "P2P Unsupported"
                    WifiP2pManager.BUSY -> "Busy"
                    else -> "Reason $reason"
                }
                callback.onStatusChanged("Discovery failed: $msg")
                Log.e(TAG, "P2P discovery failed: $msg")
            }
        })
    }

    fun stop() {
        try {
            context.unregisterReceiver(receiver)
        } catch (_: Exception) {}
        try {
            manager.stopPeerDiscovery(channel, null)
            manager.removeGroup(channel, null)
        } catch (_: Exception) {}
    }
}
