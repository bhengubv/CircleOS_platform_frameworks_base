/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.os.Build;
import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Phase 9: device enrollment / registration.
 *
 * <p>Posts device metadata to {@code POST /api/os/devices/enrol} on each
 * boot-completed so the fleet registry always reflects current device state
 * (model, version, channel, build fingerprint).
 *
 * <p>The device_id_hash is a stable {@code SHA-256(Build.ID)} so the server
 * can track history per device without storing a reversible identifier.
 *
 * <p>All calls are fire-and-forget — failures are logged but not propagated.
 */
public class DeviceEnrollment {

    private static final String TAG = "DeviceEnrollment";

    private static final String DEFAULT_BASE_URL   = "https://sleptonapi.thegeeknetwork.co.za";
    private static final int    CONNECT_TIMEOUT_MS = 10_000;
    private static final int    READ_TIMEOUT_MS    = 10_000;

    /**
     * Registers or refreshes the device in the fleet registry.
     * Must be called on a background thread.
     *
     * @param channel The device's current release channel.
     */
    public void enrol(String channel) {
        try {
            String body = buildPayload(channel);
            post(body);
        } catch (Exception e) {
            Log.w(TAG, "Enrolment failed: " + e.getMessage());
        }
    }

    private String buildPayload(String channel) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("deviceIdHash",     getDeviceIdHash());
        obj.put("channel",          channel != null ? channel : "stable");
        obj.put("osVersion",        Build.VERSION.RELEASE);
        obj.put("buildFingerprint", Build.FINGERPRINT);
        obj.put("model",            Build.MODEL);
        obj.put("hardware",         Build.HARDWARE);
        obj.put("manufacturer",     Build.MANUFACTURER);
        obj.put("product",          Build.PRODUCT);
        obj.put("sdkInt",           Build.VERSION.SDK_INT);
        return obj.toString();
    }

    private void post(String jsonBody) throws Exception {
        String baseUrl = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String urlStr  = baseUrl + "/api/os/devices/enrol";

        byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("User-Agent",
                "CircleOS-UpdateService/" + Build.VERSION.RELEASE);
        conn.setFixedLengthStreamingMode(bodyBytes.length);
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
        }

        int code = conn.getResponseCode();
        if (code == 204 || code == 200) {
            Log.d(TAG, "Device enrolled: " + Build.MODEL + " v" + Build.VERSION.RELEASE);
        } else {
            Log.w(TAG, "Enrolment endpoint returned HTTP " + code);
        }
        conn.disconnect();
    }

    // ── Device ID hash (shared across update stack) ───────────────────────────

    private static volatile String sDeviceIdHash;

    static String getDeviceIdHash() {
        if (sDeviceIdHash != null) return sDeviceIdHash;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(Build.ID.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            sDeviceIdHash = sb.toString();
        } catch (Exception e) {
            sDeviceIdHash = "unknown_" + Build.ID.hashCode();
        }
        return sDeviceIdHash;
    }
}
