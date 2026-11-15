# HicarScreen

An autonomous, zero-SDK wireless Huawei HiCar receiver implemented purely in Kotlin for Android.

## Overview

HicarScreen turns any standard Android device (in-car infotainment screen, tablet, or phone) into a wireless Huawei HiCar display and audio receiver. It does not rely on proprietary Huawei car-kit SDKs or closed-source system libraries (`libsoftbus`, `HwNearby`, etc.). All core protocols—from BLE discovery and Wi-Fi P2P negotiation to PAKE authentication, RTSP video streaming, UIBC touch control, and DMSDP virtual speaker audio—are implemented autonomously in clean Kotlin code.

## Key Features

- **Autonomous Protocol Stack**:
  - **BLE Discovery**: Custom Manufacturer Data (`0x027D` Huawei) matching HiCar automotive broadcast signatures.
  - **Wi-Fi P2P Group Owner**: Direct 5 GHz Wi-Fi Direct link establishment with automatic IP assignment.
  - **PAKE Authentication**: Autonomous password-authenticated key exchange handshake emulation.
- **H.264 Video Streaming**:
  - Built-in RTSP server (`DESCRIBE`, `SETUP`, `PLAY`).
  - RTP depacketization (handling `0x8060` RTP payloads and SPS/PPS parameter sets).
  - Hardware-accelerated decoding via Android `MediaCodec` and zero-copy rendering to `SurfaceView`.
- **Low-Latency Multi-Touch (UIBC)**:
  - User Input Back Channel touch event packetization (`0x8088` format).
  - Multi-touch coordinate transformation (down, move, up) enabling full control of the HiCar launcher and apps from the car screen.
- **High-Definition Audio (DMSDP VirSpk)**:
  - DMSDP channel multiplexing (`0xFEDCBA03` VirSpk channel).
  - Dynamic ADTS framing and `MediaCodec` AAC-LC real-time audio decoding.
  - 48 kHz stereo 16-bit PCM playback via Android `AudioTrack`.

## Project Structure

```
app/src/main/java/com/hicar/explorer/
├── MainActivity.kt        # Main UI, SurfaceView lifecycle, touch event routing
├── HiCarServer.kt         # Core protocol engine (PAKE, RTSP, UIBC, DMSDP dispatcher)
├── H264RtpDecoder.kt     # RTP H.264 packet parser & MediaCodec video decoder
├── AacAudioPlayer.kt      # DMSDP AAC audio stream decoder & AudioTrack player
├── BleAdvertiser.kt       # BLE advertisement for discovery
├── HiCarBtServer.kt       # Bluetooth RFCOMM / BR-EDR control link
└── WifiDirectManager.kt   # Wi-Fi Direct (P2P-GO) manager
```

## Getting Started

### Prerequisites
- Android Studio Ladybug / Koala / Hedgehog
- Android SDK 34
- Minimum Android Version: Android 7.0 (API Level 24)
- A device with Wi-Fi Direct and BLE Peripheral mode support

### Build & Run
```bash
./gradlew assembleDebug
```
Install the generated APK onto your target Android device:
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## License
Apache License 2.0
