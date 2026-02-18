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
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Phase 6: centralised OS policy enforcement.
 *
 * <p>On each update-check cycle, {@link #fetchAndApply(String)} polls the
 * SleptOn API for the current OS policy for the device's channel and applies
 * the following controls:
 *
 * <ul>
 *   <li><b>min_version</b> — if the running version is older than the minimum
 *       required, the update check is forced regardless of the normal 12-hour
 *       schedule.</li>
 *   <li><b>force_update_by</b> — if a deadline timestamp is set and has passed,
 *       the update is marked as mandatory so the user cannot defer it.</li>
 *   <li><b>feature_flags</b> — JSON object whose boolean fields are applied as
 *       transient system properties under the {@code circleos.flags.} namespace.
 *       Examples:
 *       <ul>
 *         <li>{@code mesh_delivery_enabled} → {@code circleos.flags.mesh_delivery}</li>
 *         <li>{@code delta_updates_enabled} → {@code circleos.flags.delta_updates}</li>
 *         <li>{@code background_check_interval_hours} → stored in policy cache</li>
 *       </ul>
 *   </li>
 *   <li><b>config_bundle</b> — JSON object carrying arbitrary config overrides
 *       (e.g. update_server_url).  Values are applied as system properties under
 *       {@code circleos.config.*}.</li>
 * </ul>
 *
 * <p>The last-fetched policy is cached to disk so that it can be enforced even
 * when the network is unavailable.
 */
public class OtaPolicyManager {

    private static final String TAG = "OtaPolicyManager";

    private static final String DEFAULT_BASE_URL = "https://sleptonapi.thegeeknetwork.co.za";
    private static final String POLICY_CACHE_FILE =
            "/data/system/circleos_update/policy_cache.json";

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 10_000;

    // ── Public result type ────────────────────────────────────────────────────

    /** Parsed and enforced policy state returned to CircleUpdateService. */
    public static final class PolicyResult {
        /** True when the current version is below min_version. */
        public final boolean forceCheckNow;
        /**
         * True when force_update_by has passed.  The UI should not offer a
         * "Later" option and notifications should be non-dismissible.
         */
        public final boolean isMandatory;
        /**
         * Background check interval in hours as set by the server.
         * Defaults to 12 when not specified.
         */
        public final int     checkIntervalHours;

        PolicyResult(boolean forceCheckNow, boolean isMandatory, int checkIntervalHours) {
            this.forceCheckNow     = forceCheckNow;
            this.isMandatory       = isMandatory;
            this.checkIntervalHours = checkIntervalHours;
        }

        @Override
        public String toString() {
            return "PolicyResult{forceCheck=" + forceCheckNow
                    + ", mandatory=" + isMandatory
                    + ", checkIntervalH=" + checkIntervalHours + "}";
        }
    }

    // ── Implementation ────────────────────────────────────────────────────────

    /**
     * Fetches the current policy for {@code channel} from the SleptOn API,
     * caches it, and applies feature flags + config bundle as system properties.
     *
     * <p>Must be called on a background thread.
     *
     * @param channel The release channel to fetch policy for.
     * @return A {@link PolicyResult} derived from the fetched (or cached) policy.
     */
    public PolicyResult fetchAndApply(String channel) {
        JSONObject policy = fetchPolicy(channel);
        if (policy == null) {
            policy = loadCachedPolicy();
        }
        if (policy == null) {
            Log.w(TAG, "No policy available (network unavailable and no cache) — using defaults");
            return new PolicyResult(false, false, 12);
        }
        cachePolicy(policy);
        return applyPolicy(policy);
    }

    // ── Network fetch ─────────────────────────────────────────────────────────

    private JSONObject fetchPolicy(String channel) {
        String baseUrl = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String urlStr  = baseUrl + "/api/os/policy?channel=" + channel;
        Log.d(TAG, "Fetching policy: GET " + urlStr);

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            int code = conn.getResponseCode();
            if (code == 404) {
                Log.d(TAG, "No policy defined for channel=" + channel);
                return null;
            }
            if (code != 200) {
                Log.w(TAG, "Policy endpoint returned HTTP " + code);
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
            }

            JSONObject obj = new JSONObject(sb.toString());
            Log.i(TAG, "Policy fetched for channel=" + channel);
            return obj;

        } catch (Exception e) {
            Log.w(TAG, "Policy fetch failed: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ── Apply ─────────────────────────────────────────────────────────────────

    private PolicyResult applyPolicy(JSONObject policy) {
        String runningVersion = SystemProperties.get(
                "ro.build.version.release_or_codename", "0.0.0");
        String minVersion     = policy.optString("minVersion", "0.0.0");
        String forceByStr     = policy.optString("forceUpdateBy", null);

        // ── Feature flags ─────────────────────────────────────────────────────
        JSONObject flags = policy.optJSONObject("featureFlags");
        int checkIntervalHours = 12;
        if (flags != null) {
            applyBoolFlag(flags, "mesh_delivery_enabled",  "circleos.flags.mesh_delivery");
            applyBoolFlag(flags, "delta_updates_enabled",  "circleos.flags.delta_updates");
            applyBoolFlag(flags, "allow_metered_download", "circleos.flags.metered_download");
            checkIntervalHours = flags.optInt("background_check_interval_hours", 12);
        }

        // ── Config bundle ─────────────────────────────────────────────────────
        JSONObject config = policy.optJSONObject("configBundle");
        if (config != null) {
            String updateUrl = config.optString("update_server_url", null);
            if (updateUrl != null && !updateUrl.isEmpty()) {
                try {
                    SystemProperties.set("circleos.config.update_url", updateUrl);
                } catch (Exception e) {
                    Log.d(TAG, "Cannot set update_url property: " + e.getMessage());
                }
            }
        }

        // ── min_version enforcement ───────────────────────────────────────────
        boolean forceCheckNow = compareVersions(runningVersion, minVersion) < 0;
        if (forceCheckNow) {
            Log.w(TAG, "Device v" + runningVersion + " is below min_version v" + minVersion
                    + " — forcing update check");
        }

        // ── force_update_by deadline ──────────────────────────────────────────
        boolean isMandatory = false;
        if (forceByStr != null && !forceByStr.isEmpty()) {
            try {
                java.time.Instant deadline = java.time.Instant.parse(forceByStr);
                isMandatory = java.time.Instant.now().isAfter(deadline);
                if (isMandatory) {
                    Log.w(TAG, "force_update_by deadline " + forceByStr
                            + " has passed — update is mandatory");
                }
            } catch (Exception e) {
                Log.w(TAG, "Cannot parse force_update_by: " + forceByStr);
            }
        }

        PolicyResult result = new PolicyResult(forceCheckNow || isMandatory,
                isMandatory, checkIntervalHours);
        Log.i(TAG, "Policy applied: " + result);
        return result;
    }

    private static void applyBoolFlag(JSONObject flags, String key, String prop) {
        if (flags.has(key)) {
            try {
                SystemProperties.set(prop, flags.optBoolean(key, true) ? "1" : "0");
            } catch (Exception e) {
                Log.d(TAG, "Cannot set property " + prop + ": " + e.getMessage());
            }
        }
    }

    // ── Policy cache ──────────────────────────────────────────────────────────

    private void cachePolicy(JSONObject policy) {
        try {
            new File(POLICY_CACHE_FILE).getParentFile().mkdirs();
            try (FileWriter fw = new FileWriter(POLICY_CACHE_FILE)) {
                fw.write(policy.toString());
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to cache policy: " + e.getMessage());
        }
    }

    private JSONObject loadCachedPolicy() {
        File f = new File(POLICY_CACHE_FILE);
        if (!f.exists()) return null;
        try (FileReader fr = new FileReader(f)) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[8192];
            int n;
            while ((n = fr.read(buf)) > 0) sb.append(buf, 0, n);
            return new JSONObject(sb.toString());
        } catch (Exception e) {
            Log.w(TAG, "Failed to load cached policy: " + e.getMessage());
            return null;
        }
    }

    // ── Version comparison ────────────────────────────────────────────────────

    /**
     * Compares two semver strings (major.minor.patch).
     * Returns negative if a < b, 0 if equal, positive if a > b.
     */
    static int compareVersions(String a, String b) {
        int[] pa = parseSemver(a);
        int[] pb = parseSemver(b);
        for (int i = 0; i < 3; i++) {
            int diff = pa[i] - pb[i];
            if (diff != 0) return diff;
        }
        return 0;
    }

    private static int[] parseSemver(String v) {
        int[] parts = new int[3];
        if (v == null) return parts;
        String[] segments = v.split("\\.");
        for (int i = 0; i < Math.min(segments.length, 3); i++) {
            try {
                parts[i] = Integer.parseInt(segments[i].replaceAll("[^0-9]", ""));
            } catch (NumberFormatException ignored) {}
        }
        return parts;
    }
}
