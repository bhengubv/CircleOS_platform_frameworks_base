/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.telecom;

import android.content.Context;
import android.os.Binder;
import android.util.Slog;

import com.circleos.server.privacy.CirclePrivacyManagerService;
import com.circleos.server.privacy.PrivacyRulesEngine;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Provides sanitised (fake) device identifiers when PrivacyRulesEngine
 * returns Action.FAKE for the calling package.
 *
 * Hooks are applied via patches in:
 *   - TelephonyManager  → getDeviceId(), getImei(), getMeid()
 *   - WifiInfo          → getMacAddress()
 *   - Settings.Secure   → ANDROID_ID
 *   - AdvertisingIdClient (via Play Services stub) → getId()
 *
 * All fake values are stable per-session (regenerated on reboot) to avoid
 * breaking apps that cache the identifier, while still preventing tracking.
 */
public class FakeResponseProvider {

    private static final String TAG = "CircleFakeResponse";

    // Stable fake IMEI — all zeros, valid Luhn check
    public static final String FAKE_IMEI = "000000000000000";

    // Stable fake MEID
    public static final String FAKE_MEID = "00000000000000";

    // All-zeros advertising ID — signals opt-out to ad networks
    public static final String FAKE_AD_ID =
            "00000000-0000-0000-0000-000000000000";

    // Per-session randomised MAC (regenerated on each boot)
    private static final String sSessionMac = generateSessionMac();

    // Per-session randomised Android ID
    private static final String sSessionAndroidId = generateSessionId();

    private final Context             mContext;
    private final PrivacyRulesEngine  mRulesEngine;

    public FakeResponseProvider(Context context, PrivacyRulesEngine rulesEngine) {
        mContext     = context;
        mRulesEngine = rulesEngine;
    }

    // ---- Public API (called from TelephonyManager / WifiInfo hooks) ----

    /**
     * Returns FAKE_IMEI if the calling package's policy says FAKE,
     * otherwise returns the real IMEI passed in.
     */
    public String getImei(String realImei, String callingPackage) {
        PrivacyRulesEngine.Action action = mRulesEngine.evaluateIdentifier(
                null, "android.permission.READ_PHONE_STATE");
        if (action == PrivacyRulesEngine.Action.FAKE) {
            Slog.d(TAG, "IMEI faked for " + callingPackage);
            return FAKE_IMEI;
        }
        return realImei;
    }

    /**
     * Returns a session-stable randomised MAC address if policy says FAKE.
     */
    public String getMacAddress(String realMac, String callingPackage) {
        PrivacyRulesEngine.Action action = mRulesEngine.evaluateIdentifier(
                null, "android.permission.ACCESS_WIFI_STATE");
        if (action == PrivacyRulesEngine.Action.FAKE) {
            Slog.d(TAG, "MAC faked for " + callingPackage);
            return sSessionMac;
        }
        return realMac;
    }

    /**
     * Returns FAKE_AD_ID (zero UUID) unconditionally — advertising ID
     * is always faked by Circle OS policy.
     */
    public String getAdvertisingId(String callingPackage) {
        Slog.d(TAG, "Ad ID faked for " + callingPackage);
        return FAKE_AD_ID;
    }

    /**
     * Returns a session-stable randomised Android ID if policy says FAKE.
     */
    public String getAndroidId(String realId, String callingPackage) {
        PrivacyRulesEngine.Action action = mRulesEngine.evaluateIdentifier(
                null, "android.permission.READ_PHONE_STATE");
        if (action == PrivacyRulesEngine.Action.FAKE) {
            Slog.d(TAG, "Android ID faked for " + callingPackage);
            return sSessionAndroidId;
        }
        return realId;
    }

    // ---- Private ----

    /** Generates a locally administered, unicast random MAC address. */
    private static String generateSessionMac() {
        SecureRandom r = new SecureRandom();
        byte[] mac = new byte[6];
        r.nextBytes(mac);
        mac[0] = (byte) ((mac[0] & 0xFE) | 0x02); // locally administered, unicast
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    /** Generates a random 16-character hex string as a fake Android ID. */
    private static String generateSessionId() {
        SecureRandom r = new SecureRandom();
        byte[] id = new byte[8];
        r.nextBytes(id);
        StringBuilder sb = new StringBuilder(16);
        for (byte b : id) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
