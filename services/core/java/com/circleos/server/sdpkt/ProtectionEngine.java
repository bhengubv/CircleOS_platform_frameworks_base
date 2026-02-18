/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Handler;
import android.util.Log;

import za.co.circleos.sdpkt.LocationContext;
import za.co.circleos.sdpkt.TransactionResult;

/**
 * SDPKT Titanium Protection Engine.
 *
 * Central decision point for whether to allow, block, or silently deceive
 * during an attempted NFC transfer. Integrates:
 *   - Location context (WalletLocationManager) → per-tap and daily limits
 *   - Stress detection (StressDetector) → coercion/distress detection
 *   - WalletStore → balance and accumulated daily spend
 *
 * Deceptive denial (anti-coercion):
 *   When stress is detected the engine returns ERR_INTERNAL with message
 *   "Network error" — indistinguishable from a connectivity failure to the
 *   attacker. The victim sees nothing immediately; 5 minutes later, when
 *   the cooldown expires and sensors have calmed, a notification is posted:
 *   "Protection was activated during a recent payment attempt."
 *
 * Normal denial (limits exceeded):
 *   Returns the appropriate TransactionResult error code (LIMIT_EXCEEDED,
 *   INSUFFICIENT_FUNDS, PROTECTION_LOCATION, PROTECTION_STRESS).
 */
public class ProtectionEngine {

    private static final String TAG              = "SdpktProtection";
    private static final String NOTIF_CHANNEL_ID = "circle_sdpkt_protection";
    private static final int    NOTIF_ID_STRESS  = 9001;
    /** Delay before posting the "protection activated" notification (ms). */
    private static final long   NOTIF_DELAY_MS   = 5 * 60 * 1000L; // 5 min

    private final Context              mContext;
    private final WalletLocationManager mLocationManager;
    private final StressDetector        mStressDetector;
    private final WalletStore           mWalletStore;
    private final Handler               mWorkerHandler;

    private boolean mNotifChannelCreated = false;

    public ProtectionEngine(Context ctx,
                            WalletLocationManager lm,
                            StressDetector sd,
                            WalletStore store,
                            Handler workerHandler) {
        mContext         = ctx;
        mLocationManager = lm;
        mStressDetector  = sd;
        mWalletStore     = store;
        mWorkerHandler   = workerHandler;

        // Listen for stress events to schedule the delayed notification
        mStressDetector.setListener(new StressDetector.StressListener() {
            @Override
            public void onStressActivated(int score) {
                Log.w(TAG, "Stress activated (score=" + score + ") — scheduling safe notification");
                scheduleStressNotification();
            }
            @Override
            public void onStressCleared() {
                Log.i(TAG, "Stress cleared");
            }
        });
    }

    /* ── Decision API ──────────────────────────────────────── */

    /**
     * Evaluate whether to allow an outbound transfer.
     *
     * @param amountCents  Transfer amount in cents.
     * @param lockScreen   True if request comes from the lock screen.
     * @return TransactionResult.ok() if allowed, or a specific failure result.
     */
    public TransactionResult evaluateTransfer(long amountCents, boolean lockScreen) {

        // ── 1. Stress check (highest priority — deceptive deny) ──────
        if (mStressDetector.isProtectionActive()) {
            Log.w(TAG, "Transfer blocked — stress protection active (score="
                    + mStressDetector.getStressScore() + ")");
            // Deceptive response: looks like a network error
            return TransactionResult.fail(
                    TransactionResult.ERR_INTERNAL, "Network error");
        }

        // ── 2. Lock screen hard cap ──────────────────────────────────
        if (lockScreen) {
            long lockLimit = WalletStore.DEFAULT_LOCKSCREEN_CENTS;
            if (amountCents > lockLimit) {
                return TransactionResult.fail(
                        TransactionResult.ERR_LIMIT_EXCEEDED,
                        "Lock screen limit: " + formatCents(lockLimit));
            }
        }

        // ── 3. Location-based limits ─────────────────────────────────
        LocationContext loc = mLocationManager.getCurrentContext();
        if (amountCents > loc.perTapLimitCents) {
            Log.i(TAG, "Transfer blocked — location limit (" + loc.typeName()
                    + " per-tap=" + loc.perTapLimitCents + ")");
            return TransactionResult.fail(
                    TransactionResult.ERR_PROTECTION_LOCATION,
                    "Location limit (" + loc.typeName() + "): "
                    + formatCents(loc.perTapLimitCents) + " per tap");
        }

        // ── 4. Balance and store-level checks ────────────────────────
        //    Use location-based limits for per-tap and daily caps.
        //    Offline accumulation cap is always enforced in WalletStore.
        boolean debited = mWalletStore.debit(
                amountCents, loc.perTapLimitCents, loc.dailyLimitCents);
        if (!debited) {
            // Determine why
            long balance = mWalletStore.getBalance().availableCents;
            if (amountCents > balance) {
                return TransactionResult.fail(
                        TransactionResult.ERR_INSUFFICIENT_FUNDS,
                        "Insufficient funds");
            }
            long dailyRemaining = mWalletStore.getDailyRemainingCents();
            if (amountCents > dailyRemaining) {
                return TransactionResult.fail(
                        TransactionResult.ERR_LIMIT_EXCEEDED,
                        "Daily limit reached");
            }
            return TransactionResult.fail(
                    TransactionResult.ERR_OFFLINE_LIMIT,
                    "Offline accumulation limit reached");
        }

        // ── Approved ─────────────────────────────────────────────────
        za.co.circleos.sdpkt.WalletBalance bal = mWalletStore.getBalance();
        Log.i(TAG, "Transfer approved: " + amountCents + " cents"
                + " location=" + loc.typeName()
                + " balance_after=" + bal.availableCents);
        return TransactionResult.ok("pending", bal.availableCents, bal.dailyRemainingCents());
    }

    /* ── Query API ─────────────────────────────────────────── */

    public LocationContext getCurrentLocationContext() {
        return mLocationManager.getCurrentContext();
    }

    public boolean isProtectionActive() {
        return mStressDetector.isProtectionActive();
    }

    public int getStressScore() {
        return mStressDetector.getStressScore();
    }

    /* ── Deceptive denial notification ────────────────────── */

    /**
     * Schedule a "Protection was activated" notification to be posted
     * NOTIF_DELAY_MS after stress is detected — by which point the user
     * is presumably away from the coercive situation.
     */
    private void scheduleStressNotification() {
        mWorkerHandler.postDelayed(this::postStressNotification, NOTIF_DELAY_MS);
    }

    private void postStressNotification() {
        // Only notify if stress has since cleared (user is presumably safe)
        if (mStressDetector.isProtectionActive()) {
            // Still stressed — reschedule
            Log.d(TAG, "Still stressed — deferring protection notification");
            scheduleStressNotification();
            return;
        }

        try {
            NotificationManager nm =
                    mContext.getSystemService(NotificationManager.class);
            if (nm == null) return;

            ensureNotifChannel(nm);

            Notification notif = new Notification.Builder(mContext, NOTIF_CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentTitle("Payment protection activated")
                    .setContentText(
                        "A recent payment attempt was blocked for your safety. "
                        + "No money was transferred.")
                    .setAutoCancel(true)
                    .setPriority(Notification.PRIORITY_HIGH)
                    .build();

            nm.notify(NOTIF_ID_STRESS, notif);
            Log.i(TAG, "Posted protection notification");
        } catch (Exception e) {
            Log.e(TAG, "Failed to post stress notification", e);
        }
    }

    private void ensureNotifChannel(NotificationManager nm) {
        if (mNotifChannelCreated) return;
        NotificationChannel ch = new NotificationChannel(
                NOTIF_CHANNEL_ID,
                "Shongololo Wallet Protection",
                NotificationManager.IMPORTANCE_HIGH);
        ch.setDescription("Alerts when payment protection is activated");
        nm.createNotificationChannel(ch);
        mNotifChannelCreated = true;
    }

    /* ── Helper ─────────────────────────────────────────────── */

    private String formatCents(long cents) {
        return String.format(java.util.Locale.US, "₷%,d.%02d",
                cents / 100, Math.abs(cents % 100));
    }
}
