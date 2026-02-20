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

import za.co.circleos.sdpkt.DeviceLink;
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
    private PersonalityModeAdapter      mPersonality;   // Phase 4
    private ProtectionLog               mProtectionLog; // Phase 5
    private CalibrationManager          mCalibration;   // Phase 5
    /** Provider for linked device map — set in Phase 6 to enforce per-device spending limits. */
    private java.util.function.Supplier<java.util.Map<String, DeviceLink>> mLinkedDevicesProvider;

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
     * @param amountCents    Transfer amount in cents.
     * @param lockScreen     True if request comes from the lock screen.
     * @return TransactionResult.ok() if allowed, or a specific failure result.
     */
    public TransactionResult evaluateTransfer(long amountCents, boolean lockScreen) {
        return evaluateTransfer(amountCents, lockScreen, null);
    }

    /**
     * Evaluate whether to allow an outbound transfer, with optional secondary device context.
     *
     * @param amountCents    Transfer amount in cents.
     * @param lockScreen     True if request comes from the lock screen.
     * @param senderDeviceId Device ID of the linked device initiating the payment,
     *                       or null for the primary device (no per-device limit applied).
     * @return TransactionResult.ok() if allowed, or a specific failure result.
     */
    public TransactionResult evaluateTransfer(long amountCents, boolean lockScreen,
            String senderDeviceId) {

        // ── 1. Stress check (highest priority — deceptive deny) ──────
        if (mStressDetector.isProtectionActive()) {
            int score = mStressDetector.getStressScore();
            Log.w(TAG, "Transfer blocked — stress protection active (score=" + score + ")");
            logEvent(ProtectionEvent.TYPE_STRESS_BLOCK, amountCents,
                     "stress score " + score + " > " + 70, null);
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

        // ── 2.5. Secondary device spending limit ────────────────────
        if (senderDeviceId != null && mLinkedDevicesProvider != null) {
            java.util.Map<String, DeviceLink> devices = mLinkedDevicesProvider.get();
            if (devices != null) {
                DeviceLink link = devices.get(senderDeviceId);
                if (link != null
                        && link.role == DeviceLink.ROLE_SECONDARY
                        && link.spendingLimitSats > 0) {
                    // spendingLimitSats is in satoshis; 1 ₷ = 100 cents, 1 sat = 0.01 cents
                    // treat spendingLimitSats as a per-tap cap in cents directly
                    // (stored as cents internally despite the field name for UI clarity)
                    long limitCents = link.spendingLimitSats;
                    if (amountCents > limitCents) {
                        Log.i(TAG, "Transfer blocked — secondary device limit"
                                + " device=" + link.shortId()
                                + " limit=" + formatCents(limitCents)
                                + " requested=" + formatCents(amountCents));
                        logEvent(ProtectionEvent.TYPE_LIMIT_BLOCK, amountCents,
                                "secondary device " + link.shortId()
                                        + " limit=" + formatCents(limitCents),
                                null);
                        return TransactionResult.fail(
                                TransactionResult.ERR_LIMIT_EXCEEDED,
                                "Device limit (" + (link.label != null ? link.label : link.shortId())
                                        + "): " + formatCents(limitCents) + " per tap");
                    }
                }
            }
        }

        // ── 3. Location + personality limits ────────────────────────
        LocationContext loc = mLocationManager.getCurrentContext();
        long effectivePerTap = (mPersonality != null)
                ? mPersonality.effectivePerTapCents(loc.perTapLimitCents, loc.dailyLimitCents, lockScreen)
                : loc.perTapLimitCents;
        long effectiveDaily = (mPersonality != null)
                ? mPersonality.effectiveDailyCents(loc.dailyLimitCents)
                : loc.dailyLimitCents;

        String limitContext = (mPersonality != null && mPersonality.getCurrentOverride() != PersonalityModeAdapter.OVERRIDE_NONE)
                ? loc.typeName() + "/" + mPersonality.overrideName()
                : loc.typeName();

        if (amountCents > effectivePerTap) {
            Log.i(TAG, "Transfer blocked — limit (" + limitContext
                    + " per-tap=" + effectivePerTap + ")");
            logEvent(ProtectionEvent.TYPE_LOCATION_BLOCK, amountCents,
                     limitContext + " per-tap=" + formatCents(effectivePerTap), loc.locationLabel);
            return TransactionResult.fail(
                    TransactionResult.ERR_PROTECTION_LOCATION,
                    "Limit (" + limitContext + "): " + formatCents(effectivePerTap) + " per tap");
        }

        // ── 4. Balance and store-level checks ────────────────────────
        //    Use effective (location + personality) limits.
        //    Offline accumulation cap is always enforced in WalletStore.
        boolean debited = mWalletStore.debit(
                amountCents, effectivePerTap, effectiveDaily);
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
                logEvent(ProtectionEvent.TYPE_LIMIT_BLOCK, amountCents,
                         "daily limit reached", loc.locationLabel);
                return TransactionResult.fail(
                        TransactionResult.ERR_LIMIT_EXCEEDED,
                        "Daily limit reached");
            }
            logEvent(ProtectionEvent.TYPE_LIMIT_BLOCK, amountCents,
                     "offline accumulation limit", loc.locationLabel);
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

    /** Wire in the Phase 4 personality mode adapter. */
    public void setPersonalityModeAdapter(PersonalityModeAdapter adapter) {
        mPersonality = adapter;
    }

    /** Wire in Phase 5 protection log and calibration manager. */
    public void setPhase5Components(ProtectionLog log, CalibrationManager calibration) {
        mProtectionLog = log;
        mCalibration   = calibration;
    }

    /**
     * Wire in Phase 6 linked devices provider so secondary device spending
     * limits can be enforced at payment time.
     *
     * @param provider Returns the live linked-device map (keyed by deviceId).
     */
    public void setLinkedDevicesProvider(
            java.util.function.Supplier<java.util.Map<String, DeviceLink>> provider) {
        mLinkedDevicesProvider = provider;
    }

    /** User-reported false positive — adjusts calibration sensitivity. */
    public void reportFalsePositive() {
        if (mCalibration != null) {
            mCalibration.reportFalsePositive(mProtectionLog);
        }
        if (mStressDetector.isProtectionActive()) {
            mStressDetector.clearProtection();
        }
    }

    /** Current calibration state for UI display. */
    public za.co.circleos.sdpkt.CalibrationState getCalibrationState() {
        if (mCalibration == null) {
            za.co.circleos.sdpkt.CalibrationState s = new za.co.circleos.sdpkt.CalibrationState();
            s.state = za.co.circleos.sdpkt.CalibrationState.STATE_CALIBRATED;
            return s;
        }
        return mCalibration.getState();
    }

    /** Recent protection events for the log UI. */
    public java.util.List<za.co.circleos.sdpkt.ProtectionEvent> getProtectionEvents(int limit) {
        if (mProtectionLog == null) return java.util.Collections.emptyList();
        return mProtectionLog.getRecent(limit);
    }

    /** Effective per-tap limit considering both location and personality mode (cents). */
    public long getEffectivePerTapCents(boolean lockScreen) {
        LocationContext loc = mLocationManager.getCurrentContext();
        if (mPersonality == null) return loc.perTapLimitCents;
        return mPersonality.effectivePerTapCents(loc.perTapLimitCents, loc.dailyLimitCents, lockScreen);
    }

    /** Effective daily limit considering both location and personality mode (cents). */
    public long getEffectiveDailyCents() {
        LocationContext loc = mLocationManager.getCurrentContext();
        if (mPersonality == null) return loc.dailyLimitCents;
        return mPersonality.effectiveDailyCents(loc.dailyLimitCents);
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

    /* ── Helpers ────────────────────────────────────────────── */

    private String formatCents(long cents) {
        return String.format(java.util.Locale.US, "₷%,d.%02d",
                cents / 100, Math.abs(cents % 100));
    }

    private void logEvent(int type, long amountCents, String reason, String locationLabel) {
        if (mProtectionLog == null) return;
        za.co.circleos.sdpkt.ProtectionEvent ev = new za.co.circleos.sdpkt.ProtectionEvent();
        ev.type          = type;
        ev.timestampMs   = System.currentTimeMillis();
        ev.amountCents   = amountCents;
        ev.reason        = reason;
        ev.locationLabel = locationLabel;
        mProtectionLog.append(ev);
    }
}
