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
 * Phase 6: reports update-state events back to the SleptOnAPI telemetry endpoint.
 *
 * <p>Each call to {@link #report(String, String, String)} POSTs a small JSON
 * payload to {@code POST /api/os/telemetry}.  The device ID is SHA-256-hashed
 * before transmission so the server never holds reversible device identifiers.
 *
 * <p>All calls are fire-and-forget (failures are logged but not propagated).
 *
 * <h3>State values</h3>
 * Use the constants in {@link UpdateState}:
 * {@code IDLE}, {@code CHECKING}, {@code DOWNLOADING}, {@code READY_TO_INSTALL},
 * {@code INSTALLING}, {@code FAILED}.
 */
public class UpdateTelemetry {

    private static final String TAG = "CircleUpdateTelemetry";

    private static final String DEFAULT_BASE_URL = "https://sleptonapi.thegeeknetwork.co.za";
    private static final int    CONNECT_TIMEOUT_MS = 8_000;
    private static final int    READ_TIMEOUT_MS    = 8_000;

    // ── Cached device ID hash ─────────────────────────────────────────────────
    private static volatile String sDeviceIdHash;

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Reports the device's current update state to the SleptOnAPI.
     *
     * <p>Must be called on a background thread (performs network I/O).
     *
     * @param channel        Current release channel (e.g. {@code "stable"}).
     * @param currentVersion Currently installed OS version (e.g. {@code "14.0.0"}).
     * @param stateName      Update state name (use {@link UpdateState#name(int)}).
     */
    public void report(String channel, String currentVersion, String stateName) {
        report(channel, currentVersion, stateName, null);
    }

    /**
     * Reports the device's current update state with an optional error message.
     *
     * @param channel        Current release channel.
     * @param currentVersion Currently installed OS version.
     * @param stateName      Update state name.
     * @param errorMessage   Optional error detail (may be null).
     */
    public void report(String channel, String currentVersion, String stateName,
            String errorMessage) {
        try {
            String body = buildPayload(channel, currentVersion, stateName, errorMessage);
            post(body);
        } catch (Exception e) {
            Log.w(TAG, "Telemetry report failed: " + e.getMessage());
        }
    }

    // ── Implementation ────────────────────────────────────────────────────────

    private String buildPayload(String channel, String currentVersion,
            String stateName, String errorMessage) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("deviceIdHash",   getDeviceIdHash());
        obj.put("channel",        channel != null ? channel : "stable");
        obj.put("currentVersion", currentVersion != null ? currentVersion : "");
        obj.put("buildId",        Build.ID);
        obj.put("updateState",    stateName != null ? stateName : "IDLE");
        if (errorMessage != null && !errorMessage.isEmpty()) {
            obj.put("errorMessage", errorMessage);
        }
        return obj.toString();
    }

    private void post(String jsonBody) throws Exception {
        String baseUrl = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String urlStr  = baseUrl + "/api/os/telemetry";

        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("User-Agent",
                "CircleOS-UpdateService/" + Build.VERSION.RELEASE);
        conn.setDoOutput(true);

        byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        conn.setFixedLengthStreamingMode(bodyBytes.length);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
        }

        int code = conn.getResponseCode();
        if (code != 204 && code != 200) {
            Log.d(TAG, "Telemetry endpoint returned HTTP " + code);
        } else {
            Log.d(TAG, "Telemetry reported: state=" + new JSONObject(jsonBody).optString("updateState"));
        }
        conn.disconnect();
    }

    // ── Device ID hashing ─────────────────────────────────────────────────────

    /**
     * Returns a stable SHA-256 hash of {@link Build#ID} so the server can track
     * per-device history without storing a reversible identifier.
     */
    private static String getDeviceIdHash() {
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
