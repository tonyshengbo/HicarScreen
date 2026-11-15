package com.hicar.explorer

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import androidx.annotation.RequiresApi
import java.util.UUID

/**
 * BleAdvertiser – Advertises the device as a HiCar car receiver.
 * On Android 4.4 (KitKat, API 19), BLE Peripheral advertising is not supported
 * by the Android framework, so it gracefully falls back to Classic Bluetooth.
 */
class BleAdvertiser(
    private val context: Context,
    private val callback: Callback
) {

    interface Callback {
        fun onStatusChanged(advertising: Boolean, detail: String)
    }

    companion object {
        private const val TAG = "BleAdvertiser"

        val HICAR_FDEE_UUID: UUID =
            UUID.fromString("0000FDEE-0000-1000-8000-00805F9B34FB")

        val HICAR_SCAN_UUID: UUID =
            UUID.fromString("d01ef33b-d575-df62-470f-96673d05bd9b")

        val HICAR_LEGACY_UUID: UUID =
            UUID.fromString("0000FE35-0000-1000-8000-00805F9B34FB")
    }

    private var lollipopImpl: LollipopAdvertiser? = null

    fun startAdvertising() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            callback.onStatusChanged(false, "BLE Advertising requires Android 5.0+. Please connect via Classic BT.")
            Log.i(TAG, "BLE Advertising not supported on Android < 5.0, skipped")
            return
        }

        if (lollipopImpl == null) {
            lollipopImpl = LollipopAdvertiser(context, callback)
        }
        lollipopImpl?.start()
    }

    fun stopAdvertising() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            lollipopImpl?.stop()
        }
    }

    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    private class LollipopAdvertiser(
        private val context: Context,
        private val callback: Callback
    ) {
        private val bluetoothManager: BluetoothManager? =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager?.adapter
        private var leAdvertiser: android.bluetooth.le.BluetoothLeAdvertiser? = null
        private var advertising = false

        private val advertiseCallback = object : android.bluetooth.le.AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: android.bluetooth.le.AdvertiseSettings?) {
                advertising = true
                callback.onStatusChanged(true, "Advertising active | UUID: FDEE + d01ef33b | Mode: LOW_LATENCY")
                Log.i(TAG, "BLE advertising started for FDEE + d01ef33b")
            }

            override fun onStartFailure(errorCode: Int) {
                advertising = false
                val reason = when (errorCode) {
                    ADVERTISE_FAILED_DATA_TOO_LARGE -> "Data too large"
                    ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> "Too many advertisers"
                    ADVERTISE_FAILED_ALREADY_STARTED -> "Already started"
                    ADVERTISE_FAILED_INTERNAL_ERROR -> "Internal error"
                    ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> "Feature unsupported"
                    else -> "Error $errorCode"
                }
                callback.onStatusChanged(false, "Failed: $reason")
                Log.e(TAG, "BLE advertising failed: $reason")
            }
        }

        fun start() {
            val adapter = bluetoothAdapter
            if (adapter == null || !adapter.isEnabled) {
                callback.onStatusChanged(false, "Bluetooth not available or disabled")
                return
            }

            leAdvertiser = adapter.bluetoothLeAdvertiser
            if (leAdvertiser == null) {
                callback.onStatusChanged(false, "BLE advertising not supported on this device")
                return
            }

            try {
                if (adapter.name != "HiCar") {
                    adapter.name = "HiCar"
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to set adapter name: ${e.message}")
            }

            val settings = android.bluetooth.le.AdvertiseSettings.Builder()
                .setAdvertiseMode(android.bluetooth.le.AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setTxPowerLevel(android.bluetooth.le.AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .setConnectable(true)
                .setTimeout(0)
                .build()

            val fdeeUuid = ParcelUuid(HICAR_FDEE_UUID)
            val seq = (((System.currentTimeMillis() / 1000) % 120) + 2).toByte()
            val fdeeData = byteArrayOf(
                0x01, 0x01, 0x01,
                0x03, 0x00, 0x04, 0x92.toByte(),
                0x04, 0x00,
                0x02, 0xBA.toByte(),
                0x10, seq,
                0xFF.toByte(), 0x01
            )

            val advertiseData = android.bluetooth.le.AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(fdeeUuid)
                .addServiceData(fdeeUuid, fdeeData)
                .build()

            val scanResponse = android.bluetooth.le.AdvertiseData.Builder()
                .setIncludeDeviceName(true)
                .addServiceUuid(ParcelUuid(HICAR_SCAN_UUID))
                .build()

            leAdvertiser?.startAdvertising(settings, advertiseData, scanResponse, advertiseCallback)
            callback.onStatusChanged(false, "Starting BLE advertising...")
        }

        fun stop() {
            if (advertising) {
                try {
                    leAdvertiser?.stopAdvertising(advertiseCallback)
                } catch (e: Exception) {
                    Log.w(TAG, "stopAdvertising: ${e.message}")
                }
            }
            advertising = false
            leAdvertiser = null
            callback.onStatusChanged(false, "Advertising stopped")
        }
    }
}
