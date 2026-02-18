/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.Log;

/**
 * Receives health data (GSR, heart rate) from a paired Wear OS companion app
 * and feeds it into {@link StressDetector} as auxiliary signals.
 *
 * The companion app broadcasts {@link #ACTION_WEAR_HEALTH_DATA} with extras:
 *   {@link #EXTRA_GSR_SCORE}  — galvanic skin response, 0-100
 *   {@link #EXTRA_HR_BPM}     — current heart rate in BPM
 *
 * Phase 5 stub: receiver is registered but StressDetector.setWearData() is a
 * no-op placeholder. Full Wear OS Wearable Data Layer integration is Phase 6.
 */
public final class WearLinkManager {

    private static final String TAG = "Sdpkt.WearLink";

    public static final String ACTION_WEAR_HEALTH_DATA =
            "za.co.circleos.sdpkt.action.WEAR_HEALTH_DATA";
    public static final String EXTRA_GSR_SCORE = "gsr_score";
    public static final String EXTRA_HR_BPM    = "hr_bpm";

    /** Wearable considered connected if data arrived within this window. */
    private static final long CONNECTED_WINDOW_MS = 30_000L;

    private final Context        mContext;
    private final StressDetector mStress;
    private BroadcastReceiver    mReceiver;

    /** Timestamp of last data packet received from wearable (0 = never). */
    private volatile long mLastDataMs   = 0;
    /** Last heart rate received from wearable companion (-1 = unknown). */
    private volatile int  mLastHrBpm    = -1;
    /** Last GSR score received from wearable companion (-1 = unknown). */
    private volatile int  mLastGsrScore = -1;

    public WearLinkManager(Context context, StressDetector stress) {
        mContext = context;
        mStress  = stress;
    }

    /** Start listening for Wear health data broadcasts. */
    public void start() {
        mReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!ACTION_WEAR_HEALTH_DATA.equals(intent.getAction())) return;
                int gsrScore = intent.getIntExtra(EXTRA_GSR_SCORE, -1);
                int hrBpm    = intent.getIntExtra(EXTRA_HR_BPM, -1);
                if (gsrScore >= 0 || hrBpm >= 0) {
                    mLastDataMs   = System.currentTimeMillis();
                    if (hrBpm >= 0)    mLastHrBpm    = hrBpm;
                    if (gsrScore >= 0) mLastGsrScore = gsrScore;
                    Log.d(TAG, "Wear data: GSR=" + gsrScore + " HR=" + hrBpm);
                    mStress.setWearData(gsrScore, hrBpm);
                }
            }
        };
        IntentFilter filter = new IntentFilter(ACTION_WEAR_HEALTH_DATA);
        mContext.registerReceiver(mReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        Log.i(TAG, "WearLinkManager started");
    }

    /**
     * Returns true if the wearable companion sent health data within the last
     * {@link #CONNECTED_WINDOW_MS} milliseconds.
     */
    public boolean isWearableConnected() {
        return mLastDataMs > 0
                && (System.currentTimeMillis() - mLastDataMs) < CONNECTED_WINDOW_MS;
    }

    /**
     * Returns the most recent heart rate in BPM received from the wearable,
     * or -1 if no data has been received yet.
     */
    public int getWearableHeartRate() { return mLastHrBpm; }

    /**
     * Returns the most recent galvanic skin response score (0-100) from the
     * wearable, or -1 if no data has been received yet.
     */
    public int getWearableGsrScore() { return mLastGsrScore; }

    /** Unregister receiver. */
    public void stop() {
        if (mReceiver != null) {
            try { mContext.unregisterReceiver(mReceiver); } catch (Exception ignored) {}
            mReceiver = null;
        }
    }
}
