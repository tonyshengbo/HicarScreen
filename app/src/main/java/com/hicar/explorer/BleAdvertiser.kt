package com.hicar.explorer

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID

/**
 * BleAdvertiser – Advertises the device as a HiCar car receiver.
 *
 * Huawei System Discovery UUIDs:
 *  - 0000FDEE-0000-1000-8000-00805F9B34FB (Huawei Nearby / Fast Pair / ScanFilter)
 *  - d01ef33b-d575-df62-470f-96673d05bd9b (HiCar BLE Service)
 *  - 0000FE35-0000-1000-8000-00805F9B34FB (HiCar Base Service)
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

    private val bluetoothManager: BluetoothManager? =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager?.adapter
    private var leAdvertiser: BluetoothLeAdvertiser? = null
    private var advertising = false

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
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

    fun startAdvertising() {
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

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        val fdeeUuid = ParcelUuid(HICAR_FDEE_UUID)
        // Huawei HiCar CloseRangeProtocol FDEE TLV payload:
        // Type 1: CloseRangeBusinessId (len 2) -> Tag 1 (iConnect), Flags 0x01 (isCloseRangeEnabled=true)
        // Type 3: ModelId (len 3) -> 0x00, 0x04, 0x92 ("000492")
        // Type 4: SubModelId (len 1) -> 0x00 ("00")
        // Type 2: ReferenceRssi (len 1) -> 0xBA (-70 dBm: rssiReal >= rssiRef -> NEARBY -> 101 FOUND)
        // Type 16: SequenceNumber (len 1) -> dynamic seq prevents cache ignores
        // Type 255 (0xFF): CustomField -> 0x01 (Crucial! Causes iConnect to pass DATA_HILINK_PARSE=[1],
        //                  activating ConnectionVersion.BLE in CarConnectService so Huawei connects GATT
        //                  and reads characteristic d01ef33b to retrieve car Bluetooth MAC)
        val seq = (((System.currentTimeMillis() / 1000) % 120) + 2).toByte()
        val fdeeData = byteArrayOf(
            0x01, 0x01, 0x01,
            0x03, 0x00, 0x04, 0x92.toByte(),
            0x04, 0x00,
            0x02, 0xBA.toByte(),
            0x10, seq,
            0xFF.toByte(), 0x01
        )

        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(fdeeUuid)
            .addServiceData(fdeeUuid, fdeeData)
            .build()

        val scanResponse = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(ParcelUuid(HICAR_SCAN_UUID))
            .build()

        leAdvertiser?.startAdvertising(settings, advertiseData, scanResponse, advertiseCallback)
        callback.onStatusChanged(false, "Starting BLE advertising...")
    }

    fun stopAdvertising() {
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
