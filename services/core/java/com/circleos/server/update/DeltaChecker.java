/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Checks whether the SleptOnAPI has a delta OTA package available to upgrade
 * directly from {@code currentVersion} to the target version.
 *
 * <p>Endpoint: {@code GET /api/os/releases/delta/{fromVersion}?channel={channel}}
 *
 * <p>Server response (JSON):
 * <pre>
 * {
 *   "delta_url":  "https://cdn.example.com/delta_1.2.0_to_1.3.0.zip",
 *   "sha256":     "abc123...",
 *   "size_bytes": 52428800
 * }
 * </pre>
 *
 * Returns {@code null} when no delta is available (HTTP 404) or on any error.
 */
public class DeltaChecker {

    private static final String TAG = "CircleDeltaChecker";

    private static final int    CONNECT_TIMEOUT_MS = 10_000;
    private static final int    READ_TIMEOUT_MS    = 10_000;
    private static final String DEFAULT_BASE_URL   =
            "https://sleptonapi.thegeeknetwork.co.za";

    // ── Public result type ────────────────────────────────────────────────────

    /** Metadata for a delta OTA package. */
    public static final class DeltaInfo {
        /** Version this delta upgrades from. */
        public final String fromVersion;
        /** Version this delta upgrades to. */
        public final String toVersion;
        /** CDN URL for the delta ZIP (contains payload.bin + payload_properties.txt). */
        public final String deltaUrl;
        /** Hex-encoded SHA-256 of the full delta ZIP file. */
        public final String sha256;
        /** Size of the delta ZIP in bytes. */
        public final long   sizeBytes;

        DeltaInfo(String fromVersion, String toVersion,
                String deltaUrl, String sha256, long sizeBytes) {
            this.fromVersion = fromVersion;
            this.toVersion   = toVersion;
            this.deltaUrl    = deltaUrl;
            this.sha256      = sha256;
            this.sizeBytes   = sizeBytes;
        }

        @Override
        public String toString() {
            return "DeltaInfo{" + fromVersion + " → " + toVersion
                    + ", size=" + sizeBytes + "}";
        }
    }

    // ── Implementation ────────────────────────────────────────────────────────

    /**
     * Queries the SleptOnAPI for a delta package from {@code fromVersion} to
     * {@code toVersion} on {@code channel}.
     *
     * <p>Must be called from a background thread.
     *
     * @param fromVersion Current OS version installed on the device.
     * @param toVersion   Target version returned by {@link UpdateChecker}.
     * @param channel     Release channel (e.g. {@code "stable"}).
     * @return {@link DeltaInfo} if a delta is available, or {@code null} otherwise.
     */
    public DeltaInfo checkDelta(String fromVersion, String toVersion, String channel) {
        if (fromVersion == null || fromVersion.isEmpty()
                || toVersion == null || toVersion.isEmpty()) {
            return null;
        }
        if (fromVersion.equals(toVersion)) {
            return null;
        }

        String baseUrl = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String urlStr  = baseUrl + "/api/os/releases/delta/" + fromVersion
                + "?channel=" + channel;

        Log.d(TAG, "Delta check: GET " + urlStr + " (target=" + toVersion + ")");

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            int code = conn.getResponseCode();
            if (code == HttpURLConnection.HTTP_NOT_FOUND) {
                Log.d(TAG, "No delta available for " + fromVersion + " → " + toVersion);
                return null;
            }
            if (code != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "Delta endpoint returned HTTP " + code);
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
            }

            JSONObject obj      = new JSONObject(sb.toString());
            String     deltaUrl = obj.getString("delta_url");
            String     sha256   = obj.getString("sha256");
            long       size     = obj.getLong("size_bytes");

            DeltaInfo info = new DeltaInfo(fromVersion, toVersion, deltaUrl, sha256, size);
            Log.i(TAG, "Delta available: " + info);
            return info;

        } catch (Exception e) {
            Log.w(TAG, "Delta check failed: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}
