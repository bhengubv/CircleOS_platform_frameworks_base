/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Represents the current calibration state of the stress-detection subsystem.
 *
 * During the first-week learning period the system collects the user's normal
 * jitter and heart-rate baseline before enforcing stress-triggered limits.
 */
public final class CalibrationState implements Parcelable {

    /** First 7 days: collecting baseline samples, protection not yet enforced. */
    public static final int STATE_LEARNING       = 0;
    /** Baseline established; protection fully active. */
    public static final int STATE_CALIBRATED     = 1;
    /** User requested re-calibration; collecting new baseline for 7 days. */
    public static final int STATE_RECALIBRATING  = 2;

    public int   state;
    /** Days remaining in learning / re-calibration period (0 if calibrated). */
    public int   daysRemaining;
    /** Learned accelerometer jitter threshold (m/s² RMS, ×100 fixed-point). */
    public int   accelThresholdCenti;
    /** Learned resting heart rate (BPM) used to anchor the stress HR floor. */
    public int   restingHeartRateBpm;
    /** Number of stress-triggered false-positive reports by the user. */
    public int   falsePositiveCount;
    /** Total accelerometer samples collected during learning. */
    public int   sampleCount;

    public CalibrationState() {}

    protected CalibrationState(Parcel in) {
        state                 = in.readInt();
        daysRemaining         = in.readInt();
        accelThresholdCenti   = in.readInt();
        restingHeartRateBpm   = in.readInt();
        falsePositiveCount    = in.readInt();
        sampleCount           = in.readInt();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(state);
        dest.writeInt(daysRemaining);
        dest.writeInt(accelThresholdCenti);
        dest.writeInt(restingHeartRateBpm);
        dest.writeInt(falsePositiveCount);
        dest.writeInt(sampleCount);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<CalibrationState> CREATOR = new Creator<CalibrationState>() {
        @Override public CalibrationState createFromParcel(Parcel in) { return new CalibrationState(in); }
        @Override public CalibrationState[] newArray(int size)        { return new CalibrationState[size]; }
    };

    public boolean isLearning() {
        return state == STATE_LEARNING || state == STATE_RECALIBRATING;
    }

    public String stateName() {
        switch (state) {
            case STATE_LEARNING:      return "learning";
            case STATE_CALIBRATED:    return "calibrated";
            case STATE_RECALIBRATING: return "recalibrating";
            default:                  return "unknown";
        }
    }
}
