/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.privacy;

import android.circleos.AppPrivacyPolicy;
import android.util.Slog;

/**
 * Stateless policy evaluator for the Circle OS privacy framework.
 *
 * Given a (package, permission, context) tuple and an {@link AppPrivacyPolicy},
 * returns one of the five actions: Allow, Deny, Fake, Ask, Log.
 *
 * Callers are responsible for persisting the result via {@link PrivacyLogger}.
 */
public class PrivacyRulesEngine {

    private static final String TAG = "CirclePrivacyRules";

    /** Possible outcomes of a policy evaluation. */
    public enum Action {
        /** Permit the operation. */
        ALLOW,
        /** Block the operation silently. */
        DENY,
        /**
         * Return a fabricated (privacy-preserving) response:
         *  - IMEI → "000000000000000"
         *  - MAC  → randomised per-session
         *  - Advertising ID → all-zeros UUID
         */
        FAKE,
        /** Show the AOSP permission dialog to let the user decide. */
        ASK,
        /** Allow but record to audit log. */
        LOG
    }

    // Known "fakeable" permissions
    private static final String PERM_IMEI  = "android.permission.READ_PHONE_STATE";
    private static final String PERM_MAC   = "android.permission.ACCESS_WIFI_STATE";
    private static final String PERM_AD_ID = "com.google.android.gms.permission.AD_ID";

    // ---- Public API ----

    /**
     * Evaluates the policy for a network permission check.
     *
     * @param policy      Active policy for the calling package.
     * @param domain      Destination domain (may be null if unknown).
     */
    public Action evaluateNetwork(AppPrivacyPolicy policy, String domain) {
        if (policy == null) {
            Slog.w(TAG, "No policy found — defaulting to DENY");
            return Action.DENY;
        }

        if (policy.lobbyMode) {
            // Lobby mode: only Circle OS CDN allowed
            return isCircleDomain(domain) ? Action.ALLOW : Action.DENY;
        }

        if (!policy.networkAllowed) {
            return Action.DENY;
        }

        if (domain != null && !policy.allowedDomains.isEmpty()) {
            return policy.allowedDomains.contains(domain) ? Action.ALLOW : Action.DENY;
        }

        return Action.ALLOW;
    }

    /**
     * Evaluates the policy for a sensor access request.
     *
     * @param policy     Active policy for the calling package.
     * @param sensorType One of: ACCELEROMETER, GYROSCOPE, BAROMETER, MAGNETOMETER.
     */
    public Action evaluateSensor(AppPrivacyPolicy policy, String sensorType) {
        if (policy == null) return Action.DENY;
        return policy.allowedSensors.contains(sensorType) ? Action.LOG : Action.DENY;
    }

    /**
     * Evaluates the policy for a contacts access request.
     */
    public Action evaluateContacts(AppPrivacyPolicy policy) {
        if (policy == null) return Action.DENY;
        if (!policy.contactsAllowed) return Action.DENY;
        return Action.LOG;
    }

    /**
     * Evaluates the policy for a storage access request.
     */
    public Action evaluateStorage(AppPrivacyPolicy policy) {
        if (policy == null) return Action.DENY;
        if (!policy.storageAllowed) return Action.DENY;
        return Action.ALLOW;
    }

    /**
     * Evaluates the policy for a device identifier access (IMEI, MAC, Ad ID).
     * Returns FAKE to return a sanitised identifier rather than the real one.
     */
    public Action evaluateIdentifier(AppPrivacyPolicy policy, String permission) {
        if (policy == null) return Action.FAKE;

        // Always fake advertising ID — no legitimate privacy-preserving reason to share it
        if (PERM_AD_ID.equals(permission)) return Action.FAKE;

        // Fake IMEI and MAC by default unless policy explicitly allows
        if (PERM_IMEI.equals(permission) || PERM_MAC.equals(permission)) {
            return Action.FAKE;
        }

        return Action.LOG;
    }

    // ---- Private ----

    private static boolean isCircleDomain(String domain) {
        if (domain == null) return false;
        return domain.endsWith(".circleos.org") || domain.endsWith(".circleos.dev");
    }
}
