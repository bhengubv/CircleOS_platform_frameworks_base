/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.util.ArrayMap;
import android.util.Log;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import za.co.circleos.personality.ManagedModePolicy;

/**
 * Manages PIN-locked personality mode policies.
 *
 * <ul>
 *   <li>Parental use: PIN-locks a mode so a child cannot leave it.</li>
 *   <li>Enterprise use: MDM app installs a policy; only the MDM app can remove it.</li>
 * </ul>
 *
 * Policies are persisted to {@code /data/system/circle/personality/managed_policies.json}.
 */
class ManagedModeManager {

    private static final String TAG       = "CirclePersonality";
    private static final String STORE_DIR  = "/data/system/circle/personality/";
    private static final String STORE_FILE = STORE_DIR + "managed_policies.json";

    private final Map<String, ManagedModePolicy> mPolicies = new ArrayMap<>();

    ManagedModeManager() {
        load();
    }

    // ---- Public API ---------------------------------------------------------

    /** Sets (or replaces) the managed policy for the given mode. */
    boolean setPolicy(ManagedModePolicy policy) {
        if (policy == null || policy.modeId == null || policy.pinHash == null) return false;
        mPolicies.put(policy.modeId, policy);
        persist();
        Log.i(TAG, "Managed policy set for mode: " + policy.modeId);
        return true;
    }

    /** Removes the policy if it is not enterprise-managed (enterprise removal requires MDM). */
    boolean clearPolicy(String modeId) {
        ManagedModePolicy p = mPolicies.get(modeId);
        if (p == null) return true; // nothing to remove
        if (p.isEnterpriseManaged) {
            Log.w(TAG, "clearPolicy blocked: enterprise-managed mode " + modeId);
            return false;
        }
        mPolicies.remove(modeId);
        persist();
        Log.i(TAG, "Managed policy cleared for mode: " + modeId);
        return true;
    }

    ManagedModePolicy getPolicy(String modeId) {
        return mPolicies.get(modeId);
    }

    boolean hasPolicy(String modeId) {
        return mPolicies.containsKey(modeId);
    }

    /**
     * Verifies the provided plain-text PIN against the stored hash.
     *
     * @return true if correct, false if wrong or no policy exists
     */
    boolean verifyPin(String modeId, String pin) {
        ManagedModePolicy p = mPolicies.get(modeId);
        if (p == null || pin == null) return false;
        String hash = sha256(pin);
        return hash != null && hash.equals(p.pinHash);
    }

    /**
     * Convenience: hash a plain-text PIN to the format stored in {@link ManagedModePolicy#pinHash}.
     */
    static String hashPin(String pin) {
        return sha256(pin);
    }

    // ---- Persistence --------------------------------------------------------

    private void load() {
        File f = new File(STORE_FILE);
        if (!f.exists()) return;
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);
            parsePolicies(sb.toString());
        } catch (Exception e) {
            Log.w(TAG, "ManagedModeManager load failed: " + e.getMessage());
        }
    }

    private void persist() {
        try {
            new File(STORE_DIR).mkdirs();
            File f = new File(STORE_FILE);
            try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(f), StandardCharsets.UTF_8))) {
                w.println(encodePolicies());
            }
        } catch (Exception e) {
            Log.e(TAG, "ManagedModeManager persist failed: " + e.getMessage());
        }
    }

    private String encodePolicies() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (ManagedModePolicy p : mPolicies.values()) {
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"modeId\":\"").append(escape(p.modeId)).append('"')
              .append(",\"pinHash\":\"").append(escape(p.pinHash)).append('"')
              .append(",\"adminPackage\":").append(p.adminPackage != null
                      ? "\"" + escape(p.adminPackage) + "\"" : "null")
              .append(",\"enterprise\":").append(p.isEnterpriseManaged)
              .append('}');
        }
        sb.append(']');
        return sb.toString();
    }

    private void parsePolicies(String json) {
        // Simple token-by-token parse — no external library dependency.
        json = json.trim();
        if (!json.startsWith("[")) return;
        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return;
        // Split on top-level },{
        int depth = 0, start = 0;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') { if (depth++ == 0) start = i; }
            else if (c == '}') {
                if (--depth == 0) {
                    ManagedModePolicy p = parsePolicy(json.substring(start, i + 1));
                    if (p != null && p.modeId != null) mPolicies.put(p.modeId, p);
                }
            }
        }
    }

    private ManagedModePolicy parsePolicy(String obj) {
        ManagedModePolicy p = new ManagedModePolicy();
        p.modeId              = extractString(obj, "modeId");
        p.pinHash             = extractString(obj, "pinHash");
        p.adminPackage        = extractString(obj, "adminPackage");
        p.isEnterpriseManaged = "true".equals(extractRaw(obj, "enterprise"));
        return p;
    }

    // ---- Helpers ------------------------------------------------------------

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private static String extractString(String obj, String key) {
        String raw = extractRaw(obj, key);
        if (raw == null || raw.equals("null")) return null;
        if (raw.startsWith("\"") && raw.endsWith("\""))
            return raw.substring(1, raw.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\");
        return raw;
    }

    private static String extractRaw(String obj, String key) {
        String search = "\"" + key + "\":";
        int idx = obj.indexOf(search);
        if (idx < 0) return null;
        int start = idx + search.length();
        int end = start;
        while (end < obj.length() && obj.charAt(end) != ',' && obj.charAt(end) != '}') end++;
        return obj.substring(start, end).trim();
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
