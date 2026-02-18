/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

import za.co.circleos.sdpkt.CalibrationState;

/**
 * Manages the first-week stress-detection baseline learning period.
 *
 * During the first 7 days after wallet creation (or after a re-calibration
 * request), the system collects accelerometer jitter and resting heart rate
 * samples to build a personal baseline. Protection is not enforced during
 * this period so legitimate behaviour is never blocked on a new device.
 *
 * After calibration, thresholds are set to:
 *   accelThreshold = baseline_rms × 2.0   (double the resting jitter)
 *   hrStressFloor  = restingHr + 30        (30 BPM above resting)
 *
 * Users can report false positives via reportFalsePositive(); after 3 reports
 * the system increases the accel threshold by 10% and logs a calibration event.
 */
public final class CalibrationManager {

    private static final String TAG = "Sdpkt.Calibration";

    private static final long LEARNING_MS      = TimeUnit.DAYS.toMillis(7);
    private static final int  DEFAULT_ACCEL_T  = 300;   // 3.00 m/s² × 100
    private static final int  DEFAULT_HR_BPM   = 90;    // default resting HR
    private static final int  FALSE_POS_LIMIT  = 3;     // reports before adjustment
    private static final float ACCEL_MULTIPLIER = 2.0f; // threshold = baseline × 2
    private static final int  HR_STRESS_DELTA  = 30;    // BPM above resting

    private final File mFile;

    private int  mState              = CalibrationState.STATE_LEARNING;
    private long mLearningStartMs    = System.currentTimeMillis();
    private int  mAccelThreshCenti   = DEFAULT_ACCEL_T;
    private int  mRestingHrBpm       = DEFAULT_HR_BPM;
    private int  mFalsePositiveCount = 0;
    private int  mSampleCount        = 0;

    // Rolling sum for baseline computation during learning
    private double mAccelRmsSum      = 0.0;
    private int    mHrSampleCount    = 0;
    private long   mHrSum            = 0;

    public CalibrationManager(File dataDir) {
        mFile = new File(dataDir, "calibration.json");
        load();
        maybeFinishLearning();
    }

    // ── Public API ────────────────────────────────────────────

    /** Called by StressDetector for every accelerometer window sample. */
    public synchronized void recordAccelSample(float rms) {
        if (!isLearning()) return;
        mAccelRmsSum += rms;
        mSampleCount++;
        maybeFinishLearning();
    }

    /** Called by StressDetector when a valid HR sample is available. */
    public synchronized void recordHrSample(int bpm) {
        if (!isLearning() || bpm <= 0) return;
        mHrSum += bpm;
        mHrSampleCount++;
        maybeFinishLearning();
    }

    /** User reported a false positive (protection triggered when it shouldn't have). */
    public synchronized void reportFalsePositive(ProtectionLog log) {
        mFalsePositiveCount++;
        if (mFalsePositiveCount % FALSE_POS_LIMIT == 0) {
            // Loosen threshold by 10%
            mAccelThreshCenti = (int) (mAccelThreshCenti * 1.1f);
            Log.i(TAG, "Loosened accel threshold after false positives → " + mAccelThreshCenti);
            if (log != null) {
                ProtectionEvent ev = new ProtectionEvent();
                ev.type        = ProtectionEvent.TYPE_CALIBRATION_ADJ;
                ev.timestampMs = System.currentTimeMillis();
                ev.reason      = "False-positive #" + mFalsePositiveCount
                               + ": threshold → " + (mAccelThreshCenti / 100.0f) + " m/s²";
                log.append(ev);
            }
        }
        save();
    }

    /** Start a 7-day re-calibration period, resetting learned values. */
    public synchronized void startRecalibration() {
        mState           = CalibrationState.STATE_RECALIBRATING;
        mLearningStartMs = System.currentTimeMillis();
        mAccelRmsSum     = 0;
        mHrSampleCount   = 0;
        mHrSum           = 0;
        mSampleCount     = 0;
        Log.i(TAG, "Re-calibration started");
        save();
    }

    public synchronized boolean isLearning() {
        return mState == CalibrationState.STATE_LEARNING
            || mState == CalibrationState.STATE_RECALIBRATING;
    }

    /** Effective accel threshold (m/s² × 100) for StressDetector. */
    public synchronized int getAccelThresholdCenti() { return mAccelThreshCenti; }

    /** Effective HR stress floor (BPM) for StressDetector. */
    public synchronized int getHrStressFloorBpm() {
        return mRestingHrBpm + HR_STRESS_DELTA;
    }

    public synchronized CalibrationState getState() {
        CalibrationState s = new CalibrationState();
        s.state               = mState;
        long elapsed          = System.currentTimeMillis() - mLearningStartMs;
        long remaining        = LEARNING_MS - elapsed;
        s.daysRemaining       = isLearning()
                                ? (int) Math.max(0, TimeUnit.MILLISECONDS.toDays(remaining))
                                : 0;
        s.accelThresholdCenti = mAccelThreshCenti;
        s.restingHeartRateBpm = mRestingHrBpm;
        s.falsePositiveCount  = mFalsePositiveCount;
        s.sampleCount         = mSampleCount;
        return s;
    }

    // ── Internal ──────────────────────────────────────────────

    private void maybeFinishLearning() {
        if (!isLearning()) return;
        long elapsed = System.currentTimeMillis() - mLearningStartMs;
        if (elapsed < LEARNING_MS) return;

        // Finalize thresholds from collected samples
        if (mSampleCount >= 100) {
            float baselineRms  = (float) (mAccelRmsSum / mSampleCount);
            mAccelThreshCenti  = Math.max(DEFAULT_ACCEL_T,
                                          (int) (baselineRms * ACCEL_MULTIPLIER * 100));
        }
        if (mHrSampleCount >= 10) {
            mRestingHrBpm = (int) (mHrSum / mHrSampleCount);
        }

        mState = CalibrationState.STATE_CALIBRATED;
        Log.i(TAG, "Calibration complete — accel=" + mAccelThreshCenti
                 + " restHR=" + mRestingHrBpm);
        save();
    }

    private void load() {
        if (!mFile.exists()) return;
        try (FileReader r = new FileReader(mFile)) {
            char[] buf = new char[(int) mFile.length()];
            int len = r.read(buf);
            if (len <= 0) return;
            JSONObject o          = new JSONObject(new String(buf, 0, len));
            mState                = o.optInt("state", CalibrationState.STATE_LEARNING);
            mLearningStartMs      = o.optLong("learningStartMs", mLearningStartMs);
            mAccelThreshCenti     = o.optInt("accelThreshCenti", DEFAULT_ACCEL_T);
            mRestingHrBpm         = o.optInt("restingHrBpm", DEFAULT_HR_BPM);
            mFalsePositiveCount   = o.optInt("falsePositiveCount", 0);
            mSampleCount          = o.optInt("sampleCount", 0);
        } catch (IOException | JSONException e) {
            Log.w(TAG, "Failed to load calibration", e);
        }
    }

    private void save() {
        try (FileWriter w = new FileWriter(mFile, false)) {
            JSONObject o = new JSONObject();
            o.put("state",              mState);
            o.put("learningStartMs",    mLearningStartMs);
            o.put("accelThreshCenti",   mAccelThreshCenti);
            o.put("restingHrBpm",       mRestingHrBpm);
            o.put("falsePositiveCount", mFalsePositiveCount);
            o.put("sampleCount",        mSampleCount);
            w.write(o.toString());
        } catch (IOException | JSONException e) {
            Log.e(TAG, "Failed to save calibration", e);
        }
    }
}
