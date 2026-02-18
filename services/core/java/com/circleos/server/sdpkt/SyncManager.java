/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Handler;
import android.util.Log;

import za.co.circleos.sdpkt.SyncStatus;
import za.co.circleos.sdpkt.ShongololoTransaction;

/**
 * Network-aware settlement sync manager.
 *
 * Listens for ConnectivityManager callbacks; when a validated network becomes
 * available, drains the SettlementQueue. Reports sync state via SyncStatus.
 *
 * State machine:
 *   OFFLINE        → (network available) → ONLINE_PENDING | SYNCED
 *   ONLINE_PENDING → (drain started)     → SYNCING
 *   SYNCING        → (drain complete)    → SYNCED
 *   SYNCED         → (network lost)      → OFFLINE
 *   any            → forceSyncNow()      → SYNCING
 *
 * Phase 2: settlement is local re-verification (no backend).
 * Phase 4: SyncManager will POST to the Circle settlement endpoint.
 */
public class SyncManager {

    private static final String TAG            = "SdpktSync";
    /** Delay before starting settlement after network becomes available (ms). */
    private static final long   SYNC_DELAY_MS  = 2_000L;

    private final Context          mContext;
    private final SettlementQueue  mQueue;
    private final Handler          mWorkerHandler;

    private int    mState          = SyncStatus.STATE_OFFLINE;
    private long   mLastSyncMs     = 0;
    private long   mOfflineSinceMs = 0;
    private int    mFailedCount    = 0;
    private boolean mNetworkAvailable = false;

    private ConnectivityManager.NetworkCallback mNetworkCallback;

    public SyncManager(Context context, SettlementQueue queue, Handler workerHandler) {
        mContext       = context;
        mQueue         = queue;
        mWorkerHandler = workerHandler;
    }

    /* ── Lifecycle ─────────────────────────────────────────── */

    /** Register connectivity listener. Call from PHASE_BOOT_COMPLETED. */
    public void start() {
        mOfflineSinceMs = System.currentTimeMillis();

        ConnectivityManager cm = mContext.getSystemService(ConnectivityManager.class);
        if (cm == null) {
            Log.w(TAG, "ConnectivityManager unavailable — sync disabled");
            return;
        }

        mNetworkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                Log.d(TAG, "Network available");
                mNetworkAvailable = true;
                mOfflineSinceMs   = 0;
                scheduleSync();
            }

            @Override
            public void onLost(Network network) {
                Log.d(TAG, "Network lost");
                mNetworkAvailable = false;
                mOfflineSinceMs   = System.currentTimeMillis();
                mState = SyncStatus.STATE_OFFLINE;
            }
        };

        NetworkRequest req = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                .build();
        cm.registerNetworkCallback(req, mNetworkCallback);
        Log.i(TAG, "SyncManager started");
    }

    /** Unregister listener. */
    public void stop() {
        if (mNetworkCallback != null) {
            ConnectivityManager cm = mContext.getSystemService(ConnectivityManager.class);
            if (cm != null) {
                try { cm.unregisterNetworkCallback(mNetworkCallback); }
                catch (Exception ignored) {}
            }
            mNetworkCallback = null;
        }
    }

    /* ── Sync control ──────────────────────────────────────── */

    /** Schedule a sync after SYNC_DELAY_MS (debounce rapid connect/disconnect). */
    private void scheduleSync() {
        mWorkerHandler.removeCallbacksAndMessages(null);
        mWorkerHandler.postDelayed(this::runSync, SYNC_DELAY_MS);
    }

    /** Trigger an immediate sync regardless of schedule. */
    public void forceSyncNow() {
        if (!mNetworkAvailable) {
            Log.d(TAG, "forceSyncNow: no network");
            return;
        }
        mWorkerHandler.removeCallbacksAndMessages(null);
        mWorkerHandler.post(this::runSync);
    }

    /** Drain the settlement queue. Runs on the worker thread. */
    private void runSync() {
        int pending = mQueue.getPendingCount();
        if (pending == 0) {
            mState     = SyncStatus.STATE_SYNCED;
            mLastSyncMs = System.currentTimeMillis();
            Log.d(TAG, "Sync: nothing pending");
            return;
        }

        Log.i(TAG, "Sync: processing " + pending + " pending transaction(s)");
        mState = SyncStatus.STATE_SYNCING;

        mQueue.setListener(new SettlementQueue.SettlementListener() {
            @Override public void onSettled(ShongololoTransaction tx) {
                Log.i(TAG, "Settled: " + tx.txId);
            }
            @Override public void onReversed(ShongololoTransaction tx, String reason) {
                mFailedCount++;
                Log.w(TAG, "Reversed: " + tx.txId + " — " + reason);
            }
        });

        mQueue.processAll();

        mState      = SyncStatus.STATE_SYNCED;
        mLastSyncMs = System.currentTimeMillis();
        Log.i(TAG, "Sync complete. failedCount=" + mFailedCount);
    }

    /* ── Status ────────────────────────────────────────────── */

    /** Return a snapshot of current sync state. */
    public SyncStatus getStatus() {
        SyncStatus s = new SyncStatus();
        s.state          = mNetworkAvailable ? mState : SyncStatus.STATE_OFFLINE;
        s.pendingCount   = mQueue.getPendingCount();
        s.failedCount    = mFailedCount;
        s.lastSyncMs     = mLastSyncMs;
        s.offlineSinceMs = mOfflineSinceMs;
        return s;
    }

    /** Number of outbound transactions waiting for settlement. */
    public int getPendingCount() {
        return mQueue.getPendingCount();
    }

    /** Reset failure counter after user acknowledgement. */
    public void clearFailedCount() {
        mFailedCount = 0;
    }
}
