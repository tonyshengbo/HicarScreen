package com.hicar.explorer.media

import android.content.Context
import android.media.AudioManager
import android.os.Build
import android.util.Log

/**
 * AudioFocusManager – Handles automotive audio focus transitions.
 * Supports Android 4.4 (KitKat, API 19) up to Android 14+ (API 34).
 */
class AudioFocusManager(
    context: Context,
    private val listener: FocusListener
) {

    interface FocusListener {
        fun onGainFocus()
        fun onLossFocus(isTransient: Boolean, canDuck: Boolean)
    }

    companion object {
        private const val TAG = "AudioFocusManager"
    }

    private val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
    private var hasFocus = false

    private val afListener = AudioManager.OnAudioFocusChangeListener { focusChange ->
        when (focusChange) {
            AudioManager.AUDIOFOCUS_GAIN -> {
                Log.i(TAG, "Audio focus GAIN")
                hasFocus = true
                listener.onGainFocus()
            }
            AudioManager.AUDIOFOCUS_LOSS -> {
                Log.i(TAG, "Audio focus LOSS (permanent)")
                hasFocus = false
                listener.onLossFocus(isTransient = false, canDuck = false)
            }
            AudioManager.AUDIOFOCUS_LOSS_TRANSIENT -> {
                Log.i(TAG, "Audio focus LOSS_TRANSIENT")
                hasFocus = false
                listener.onLossFocus(isTransient = true, canDuck = false)
            }
            AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK -> {
                Log.i(TAG, "Audio focus LOSS_TRANSIENT_CAN_DUCK")
                listener.onLossFocus(isTransient = true, canDuck = true)
            }
        }
    }

    fun requestFocus(): Boolean {
        if (hasFocus) return true
        val am = audioManager ?: return false
        val result = @Suppress("DEPRECATION") am.requestAudioFocus(
            afListener,
            AudioManager.STREAM_MUSIC,
            AudioManager.AUDIOFOCUS_GAIN
        )
        hasFocus = (result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED)
        Log.i(TAG, "Request audio focus result: $result (granted=$hasFocus)")
        return hasFocus
    }

    fun abandonFocus() {
        if (!hasFocus) return
        try {
            @Suppress("DEPRECATION")
            audioManager?.abandonAudioFocus(afListener)
        } catch (e: Exception) {
            Log.w(TAG, "abandonFocus error: ${e.message}")
        }
        hasFocus = false
        Log.i(TAG, "Abandoned audio focus")
    }
}
