/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;

import za.co.circleos.personality.ICirclePersonalityManager;
import za.co.circleos.personality.IPersonalityCallback;
import za.co.circleos.personality.PersonalityMode;
import za.co.circleos.sdpkt.LocationContext;

/**
 * Bridges the Personality Engine to SDPKT wallet limit overrides.
 *
 * Reads the active personality mode from circle.personality and maps
 * it to effective per-tap and daily transaction limits. Registers an
 * IPersonalityCallback so limits update automatically on mode switches.
 *
 * Mode → limit mapping:
 *   "secure"              → RISKY limits  (₷200/tap, ₷500/day)
 *   "travel"              → UNKNOWN limits (₷500/tap, ₷2,000/day)
 *   "party"/"social"      → elevated lock-screen (₷500), daily ₷5,000/tap ₷2,000
 *   "work"/"business"     → standard limits + audit flag
 *   everything else       → no override (use location-based limits)
 *
 * Privacy: no personal data is sent to the Personality Engine. Only the
 * mode ID string is read.
 */
public class PersonalityModeAdapter {

    private static final String TAG = "SdpktPersonality";

    /* ── Limit overrides by mode ───────────────────────────── */

    /** No personality override — use location-based limits. */
    public static final int OVERRIDE_NONE    = 0;
    /** Secure mode: conservative (RISKY) limits regardless of location. */
    public static final int OVERRIDE_SECURE  = 1;
    /** Party/social mode: elevated daily limit, relaxed lock screen. */
    public static final int OVERRIDE_PARTY   = 2;
    /** Travel mode: UNKNOWN limits (unfamiliar locations assumed). */
    public static final int OVERRIDE_TRAVEL  = 3;
    /** Work mode: standard limits + audit logging flag. */
    public static final int OVERRIDE_WORK    = 4;

    private ICirclePersonalityManager mPersonality;
    private volatile int mCurrentOverride = OVERRIDE_NONE;
    private volatile boolean mAuditMode   = false;

    /* ── Lifecycle ─────────────────────────────────────────── */

    /** Bind to circle.personality and register for mode-change callbacks. */
    public void start() {
        try {
            IBinder b = ServiceManager.getService("circle.personality");
            if (b == null) {
                Log.w(TAG, "circle.personality not available — no mode overrides");
                return;
            }
            mPersonality = ICirclePersonalityManager.Stub.asInterface(b);
            // Apply current mode immediately
            PersonalityMode mode = mPersonality.getActiveMode();
            applyMode(mode);
            // Register callback for future changes
            mPersonality.registerCallback(mCallback);
            Log.i(TAG, "Personality adapter started, active mode: "
                    + (mode != null ? mode.id : "none"));
        } catch (Exception e) {
            Log.w(TAG, "Failed to bind circle.personality: " + e.getMessage());
        }
    }

    /* ── Mode mapping ──────────────────────────────────────── */

    private void applyMode(PersonalityMode mode) {
        if (mode == null) { mCurrentOverride = OVERRIDE_NONE; return; }
        String id = mode.id != null ? mode.id.toLowerCase(java.util.Locale.US) : "";
        mAuditMode = false;

        if (id.contains("secure") || id.contains("safe") || id.contains("privacy")) {
            mCurrentOverride = OVERRIDE_SECURE;
        } else if (id.contains("party") || id.contains("social") || id.contains("night")) {
            mCurrentOverride = OVERRIDE_PARTY;
        } else if (id.contains("travel") || id.contains("abroad") || id.contains("tourist")) {
            mCurrentOverride = OVERRIDE_TRAVEL;
        } else if (id.contains("work") || id.contains("business") || id.contains("office")) {
            mCurrentOverride = OVERRIDE_WORK;
            mAuditMode = true;
        } else {
            mCurrentOverride = OVERRIDE_NONE;
        }
        Log.d(TAG, "Mode override updated: " + mCurrentOverride + " (mode=" + id + ")");
    }

    /* ── Limit resolution ──────────────────────────────────── */

    /**
     * Apply personality mode limit caps on top of location-based limits.
     * The more restrictive of (location limit, mode limit) always wins.
     *
     * @param locationPerTap  Per-tap limit from location context (cents).
     * @param locationDaily   Daily limit from location context (cents).
     * @param lockScreen      True if the request comes from the lock screen.
     * @return Effective per-tap limit in cents.
     */
    public long effectivePerTapCents(long locationPerTap, long locationDaily, boolean lockScreen) {
        switch (mCurrentOverride) {
            case OVERRIDE_SECURE:
                return Math.min(locationPerTap, LocationContext.RISKY_PER_TAP_CENTS);
            case OVERRIDE_PARTY:
                // Party: elevated lock screen (₷500 = 50,000 cents), otherwise keep location limit
                if (lockScreen) return 50_000L; // ₷500
                return locationPerTap;
            case OVERRIDE_TRAVEL:
                return Math.min(locationPerTap, LocationContext.UNKNOWN_PER_TAP_CENTS);
            default:
                return locationPerTap;
        }
    }

    /**
     * Effective daily limit considering personality mode.
     * More restrictive of (location daily, mode daily) wins.
     */
    public long effectiveDailyCents(long locationDaily) {
        switch (mCurrentOverride) {
            case OVERRIDE_SECURE:
                return Math.min(locationDaily, LocationContext.RISKY_DAILY_CENTS);
            case OVERRIDE_PARTY:
                // Party mode: up to ₷5,000/day total
                return Math.min(locationDaily, 500_000L);
            case OVERRIDE_TRAVEL:
                return Math.min(locationDaily, LocationContext.UNKNOWN_DAILY_CENTS);
            default:
                return locationDaily;
        }
    }

    /** True if the current mode requires enhanced transaction logging. */
    public boolean isAuditMode() { return mAuditMode; }

    /** Current override level (OVERRIDE_* constant). */
    public int getCurrentOverride() { return mCurrentOverride; }

    /** Human-readable name of the current mode override. */
    public String overrideName() {
        switch (mCurrentOverride) {
            case OVERRIDE_SECURE:  return "Secure";
            case OVERRIDE_PARTY:   return "Party";
            case OVERRIDE_TRAVEL:  return "Travel";
            case OVERRIDE_WORK:    return "Work";
            default:               return "None";
        }
    }

    /* ── IPersonalityCallback ──────────────────────────────── */

    private final IPersonalityCallback mCallback = new IPersonalityCallback.Stub() {
        @Override
        public void onModeChanged(PersonalityMode newMode) throws RemoteException {
            applyMode(newMode);
            Log.i(TAG, "Mode changed → override=" + mCurrentOverride);
        }
        @Override
        public void onModeAvailabilityChanged() {}
        @Override
        public void onAutoSwitchSuggestion(String modeId, String reason) {}
    };
}
