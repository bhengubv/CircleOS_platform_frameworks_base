/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.Handler;
import android.util.Log;

/**
 * Stress detector for SDPKT Titanium Protection Engine.
 *
 * Signal sources:
 *  1. Accelerometer tremor — TYPE_ACCELEROMETER
 *     High-frequency jitter in acceleration magnitude → tremor score.
 *     Window: last 50 samples (~2 s at 25 Hz sensor rate).
 *     Threshold: personalised via CalibrationManager (default 3.0 m/s² RMS).
 *
 *  2. Heart rate — TYPE_HEART_RATE (wearable/optical sensor, if available)
 *     Above resting HR + 30 BPM → elevated stress score.
 *
 *  3. Wear health data — fed by WearLinkManager when a paired Wear OS device
 *     broadcasts GSR / HR data.
 *
 * Composite stress score: 0–100.
 *   accelerometer tremor: up to 60 points
 *   heart rate spike:     up to 40 points
 *
 * Activation threshold: STRESS_THRESHOLD = 70
 * Cooldown after activation: COOLDOWN_MS = 5 minutes
 *
 * When active, ProtectionEngine returns a deceptive "network error"
 * to the payment partner so they cannot detect the block.
 */
public class StressDetector implements SensorEventListener {

    private static final String TAG              = "SdpktStress";
    private static final int    ACCEL_WINDOW     = 50;       // samples
    private static final float  ACCEL_THRESHOLD  = 3.0f;    // m/s² default RMS
    private static final float  HR_STRESS_BPM    = 120f;    // default stress floor
    private static final int    STRESS_THRESHOLD = 70;      // composite 0-100
    private static final long   COOLDOWN_MS      = 5 * 60 * 1000L; // 5 minutes

    /* ── State ─────────────────────────────────────────────── */

    private final Context mContext;
    private SensorManager mSensorManager;
    private CalibrationManager mCalibration;  // optional; set after construction (Phase 5)

    // Accelerometer ring buffer (magnitude values)
    private final float[] mAccelBuffer = new float[ACCEL_WINDOW];
    private int  mAccelIdx   = 0;
    private int  mAccelCount = 0;

    // Heart rate (most recent reading — device sensor or Wear)
    private volatile float mHeartRateBpm = 0f;
    // Wear GSR override (-1 = not available)
    private volatile int   mWearGsrScore = -1;

    // Stress state
    private volatile boolean mProtectionActive  = false;
    private volatile long    mActivatedAtMs      = 0L;
    private volatile int     mLastStressScore    = 0;

    private StressListener mListener;

    /** Callback so ProtectionEngine can react when stress is detected. */
    public interface StressListener {
        void onStressActivated(int score);
        void onStressCleared();
    }

    public StressDetector(Context ctx) {
        mContext = ctx;
    }

    public void setListener(StressListener listener) {
        mListener = listener;
    }

    /** Wire in Phase 5 CalibrationManager for personalised thresholds. */
    public void setCalibrationManager(CalibrationManager calibration) {
        mCalibration = calibration;
    }

    /**
     * Feed Wear OS health data from {@link WearLinkManager}.
     * @param gsrScore 0-100 galvanic skin response, or -1 if unavailable.
     * @param hrBpm    Heart rate in BPM, or -1 if unavailable.
     */
    public void setWearData(int gsrScore, int hrBpm) {
        if (gsrScore >= 0) mWearGsrScore = gsrScore;
        if (hrBpm > 0)     mHeartRateBpm = hrBpm;
        evaluateStress();
    }

    /* ── Lifecycle ─────────────────────────────────────────── */

    public void start(Handler workerHandler) {
        mSensorManager = (SensorManager) mContext.getSystemService(Context.SENSOR_SERVICE);
        if (mSensorManager == null) {
            Log.w(TAG, "SensorManager unavailable");
            return;
        }

        // Register accelerometer
        Sensor accel = mSensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
        if (accel != null) {
            mSensorManager.registerListener(this, accel,
                    SensorManager.SENSOR_DELAY_NORMAL, workerHandler);
            Log.i(TAG, "Accelerometer registered");
        }

        // Register heart rate if available (may only be on wearables)
        Sensor hr = mSensorManager.getDefaultSensor(Sensor.TYPE_HEART_RATE);
        if (hr != null) {
            mSensorManager.registerListener(this, hr,
                    SensorManager.SENSOR_DELAY_NORMAL, workerHandler);
            Log.i(TAG, "Heart rate sensor registered");
        } else {
            Log.d(TAG, "No heart rate sensor");
        }
    }

    public void stop() {
        if (mSensorManager != null) {
            mSensorManager.unregisterListener(this);
        }
    }

    /* ── SensorEventListener ───────────────────────────────── */

    @Override
    public void onSensorChanged(SensorEvent event) {
        switch (event.sensor.getType()) {
            case Sensor.TYPE_ACCELEROMETER:
                handleAccelerometer(event.values);
                break;
            case Sensor.TYPE_HEART_RATE:
                mHeartRateBpm = event.values[0];
                if (mCalibration != null) {
                    mCalibration.recordHrSample((int) mHeartRateBpm);
                }
                evaluateStress();
                break;
        }
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {}

    /* ── Signal processing ─────────────────────────────────── */

    private void handleAccelerometer(float[] values) {
        float mag = (float) Math.sqrt(
                values[0] * values[0] + values[1] * values[1] + values[2] * values[2]);
        mAccelBuffer[mAccelIdx % ACCEL_WINDOW] = mag;
        mAccelIdx++;
        if (mAccelCount < ACCEL_WINDOW) mAccelCount++;

        // Evaluate every full window
        if (mAccelCount >= ACCEL_WINDOW && mAccelIdx % 10 == 0) {
            evaluateStress();
        }
    }

    /** Compute composite stress score and update protection state. */
    private synchronized void evaluateStress() {
        // Personalised thresholds (fall back to defaults during calibration)
        float accelThreshold = (mCalibration != null)
                ? mCalibration.getAccelThresholdCenti() / 100.0f
                : ACCEL_THRESHOLD;
        float hrStressFloor  = (mCalibration != null && !mCalibration.isLearning())
                ? mCalibration.getHrStressFloorBpm()
                : HR_STRESS_BPM;

        // ── Accelerometer tremor score (0-60) ──────────────
        int accelScore = 0;
        if (mAccelCount > 0) {
            float sum  = 0, sumSq = 0;
            int   n    = Math.min(mAccelCount, ACCEL_WINDOW);
            for (int i = 0; i < n; i++) sum += mAccelBuffer[i];
            float mean = sum / n;
            for (int i = 0; i < n; i++) {
                float d = mAccelBuffer[i] - mean;
                sumSq += d * d;
            }
            float rms = (float) Math.sqrt(sumSq / n);
            if (mCalibration != null) mCalibration.recordAccelSample(rms);
            // Scale: 0 rms → 0, threshold rms → 60
            accelScore = (int) Math.min(60f, (rms / accelThreshold) * 60f);
        }

        // ── Wear GSR boost (if available, blended 0-20 points into accel slot) ──
        if (mWearGsrScore >= 0) {
            int gsrBoost = (int) (mWearGsrScore * 0.2f); // 100% GSR → +20
            accelScore = Math.min(60, accelScore + gsrBoost);
        }

        // ── Heart rate score (0-40) ─────────────────────────
        int hrScore = 0;
        if (mHeartRateBpm > 0) {
            if (mHeartRateBpm >= hrStressFloor) {
                hrScore = (int) Math.min(40f,
                        ((mHeartRateBpm - hrStressFloor) / 30f) * 40f + 20f);
            }
        }

        // Don't enforce stress blocks during calibration learning period
        if (mCalibration != null && mCalibration.isLearning()) {
            mLastStressScore = accelScore + hrScore;
            return;  // record score but don't trigger protection
        }

        int total = accelScore + hrScore;
        mLastStressScore = total;

        boolean wasActive = mProtectionActive;

        if (!mProtectionActive && total >= STRESS_THRESHOLD) {
            mProtectionActive = true;
            mActivatedAtMs    = System.currentTimeMillis();
            Log.w(TAG, "STRESS DETECTED — score=" + total
                    + " accel=" + accelScore + " hr=" + hrScore);
            if (mListener != null) mListener.onStressActivated(total);

        } else if (mProtectionActive) {
            // Check cooldown
            long elapsed = System.currentTimeMillis() - mActivatedAtMs;
            if (elapsed >= COOLDOWN_MS && total < STRESS_THRESHOLD) {
                mProtectionActive = false;
                Log.i(TAG, "Stress cleared after " + elapsed / 1000 + " s cooldown");
                if (mListener != null) mListener.onStressCleared();
            }
        }
    }

    /* ── Query API ─────────────────────────────────────────── */

    /** True if stress protection is currently blocking transfers. */
    public boolean isProtectionActive() {
        return mProtectionActive;
    }

    /** Current composite stress score (0-100). */
    public int getStressScore() {
        return mLastStressScore;
    }

    /** Time since protection was activated, in ms. 0 if not active. */
    public long getProtectionDurationMs() {
        if (!mProtectionActive || mActivatedAtMs == 0) return 0;
        return System.currentTimeMillis() - mActivatedAtMs;
    }

    /**
     * Force-clear protection (e.g. user has explicitly confirmed safety).
     * Resets the activation timestamp so cooldown triggers immediately.
     */
    public synchronized void clearProtection() {
        mProtectionActive = false;
        mActivatedAtMs    = 0;
        Log.i(TAG, "Protection manually cleared");
    }
}
