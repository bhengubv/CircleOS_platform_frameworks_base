/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Queries the SleptOnAPI update endpoint to check whether a newer CircleOS build is available.
 *
 * Endpoint: {baseUrl}/api/os/releases/latest?channel={channel}&current_version={version}&device_id={id}
 *
 * Expected JSON response:
 * {
 *   "has_update": true,
 *   "version": "1.2.3",
 *   "manifest_url": "https://...",
 *   "rollout_percent": 100,
 *   "min_version": "1.0.0"
 * }
 *
 * Returns null on any network or parse error.
 */
public class UpdateChecker {

    private static final String TAG = "CircleUpdateChecker";

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 10_000;

    private static final String DEFAULT_BASE_URL = "https://sleptonapi.thegeeknetwork.co.za";
    private static final String DEFAULT_CHANNEL  = "stable";

    /** Parsed response from the update server. */
    public static final class UpdateInfo {
        public final boolean hasUpdate;
        public final String  version;
        public final String  manifestUrl;
        public final int     rolloutPercent;
        public final String  minVersion;

        public UpdateInfo(boolean hasUpdate, String version, String manifestUrl,
                int rolloutPercent, String minVersion) {
            this.hasUpdate      = hasUpdate;
            this.version        = version;
            this.manifestUrl    = manifestUrl;
            this.rolloutPercent = rolloutPercent;
            this.minVersion     = minVersion;
        }

        @Override
        public String toString() {
            return "UpdateInfo{hasUpdate=" + hasUpdate
                    + ", version=" + version
                    + ", rolloutPercent=" + rolloutPercent + "}";
        }
    }

    private final Context mContext;

    /** User-persisted channel override; null means use the build property. */
    private volatile String mChannelOverride;

    public UpdateChecker(Context context) {
        mContext = context;
    }

    /** Sets a channel override that takes precedence over ro.circleos.channel. */
    public void setChannelOverride(String channel) {
        mChannelOverride = channel;
    }

    /**
     * Performs a synchronous update check. Must be called from a background thread.
     *
     * @return UpdateInfo on success (may have hasUpdate=false), or null on error.
     */
    public UpdateInfo check() {
        if (!isWifiConnected()) {
            Log.d(TAG, "Skipping update check — not on WiFi");
            return null;
        }

        String baseUrl        = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String channel        = mChannelOverride != null
                ? mChannelOverride
                : SystemProperties.get("ro.circleos.channel", DEFAULT_CHANNEL);
        String currentVersion = Build.VERSION.RELEASE;
        String deviceId       = Build.ID;

        String urlStr = baseUrl
                + "/api/os/releases/latest"
                + "?channel=" + channel
                + "&current_version=" + currentVersion
                + "&device_id=" + deviceId;

        Log.d(TAG, "Checking for updates: " + urlStr);

        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent",
                    "CircleOS-UpdateService/" + currentVersion);

            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "Update server returned HTTP " + responseCode);
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            }

            return parseResponse(sb.toString());

        } catch (Exception e) {
            Log.e(TAG, "Update check failed", e);
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private UpdateInfo parseResponse(String json) {
        try {
            JSONObject obj = new JSONObject(json);

            boolean hasUpdate      = obj.optBoolean("has_update", false);
            String  version        = obj.optString("version", null);
            String  manifestUrl    = obj.optString("manifest_url", null);
            int     rolloutPercent = obj.optInt("rollout_percent", 100);
            String  minVersion     = obj.optString("min_version", null);

            UpdateInfo info = new UpdateInfo(hasUpdate, version, manifestUrl,
                    rolloutPercent, minVersion);
            Log.d(TAG, "Parsed update response: " + info);
            return info;

        } catch (Exception e) {
            Log.e(TAG, "Failed to parse update server response", e);
            return null;
        }
    }

    private boolean isWifiConnected() {
        ConnectivityManager cm = (ConnectivityManager)
                mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;

        Network activeNetwork = cm.getActiveNetwork();
        if (activeNetwork == null) return false;

        NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
        return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
    }
}
