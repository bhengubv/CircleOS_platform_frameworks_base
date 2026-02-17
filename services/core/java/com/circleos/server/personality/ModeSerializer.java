/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.util.Log;

import java.util.ArrayList;
import java.util.List;

import za.co.circleos.personality.ModeConfig;
import za.co.circleos.personality.PersonalityMode;

/**
 * Serialises {@link PersonalityMode} objects to/from JSON without external libraries.
 * Only custom (non-Tier1) modes need to be persisted.
 */
class ModeSerializer {

    private static final String TAG = "CirclePersonality";

    private ModeSerializer() {}

    // -------------------------------------------------------------------------
    // Encode
    // -------------------------------------------------------------------------

    static String encodeMode(PersonalityMode mode) {
        if (mode == null) return "null";
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        appendStr(sb, "id",          mode.id);          sb.append(',');
        appendStr(sb, "name",        mode.name);        sb.append(',');
        appendStr(sb, "description", mode.description); sb.append(',');
        appendInt(sb, "tier",        mode.tier);        sb.append(',');
        appendBool(sb, "isCustom",   mode.isCustom);    sb.append(',');
        sb.append('"').append("config").append("\":");
        sb.append(encodeConfig(mode.config));
        sb.append('}');
        return sb.toString();
    }

    static String encodeModeList(List<PersonalityMode> modes) {
        StringBuilder sb = new StringBuilder('[');
        for (int i = 0; i < modes.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(encodeMode(modes.get(i)));
        }
        sb.append(']');
        return sb.toString();
    }

    private static String encodeConfig(ModeConfig cfg) {
        if (cfg == null) return "{}";
        StringBuilder sb = new StringBuilder('{');
        appendBool(sb, "dndEnabled",       cfg.dndEnabled);       sb.append(',');
        appendInt(sb,  "notificationLevel", cfg.notificationLevel); sb.append(',');
        appendBool(sb, "wifiEnabled",      cfg.wifiEnabled);      sb.append(',');
        appendBool(sb, "dataEnabled",      cfg.dataEnabled);      sb.append(',');
        appendBool(sb, "locationEnabled",  cfg.locationEnabled);  sb.append(',');
        appendBool(sb, "bluetoothEnabled", cfg.bluetoothEnabled); sb.append(',');
        appendInt(sb,  "screenBrightness", cfg.screenBrightness); sb.append(',');
        appendInt(sb,  "themeMode",        cfg.themeMode);        sb.append(',');
        appendBool(sb, "enforceVpn",       cfg.enforceVpn);       sb.append(',');
        appendInt(sb,  "privacyLevel",     cfg.privacyLevel);     sb.append(',');
        appendBool(sb, "cloudSyncEnabled", cfg.cloudSyncEnabled);
        sb.append('}');
        return sb.toString();
    }

    private static void appendStr(StringBuilder sb, String key, String val) {
        sb.append('"').append(key).append("\":\"");
        if (val != null) sb.append(val.replace("\"", "\\\""));
        sb.append('"');
    }

    private static void appendInt(StringBuilder sb, String key, int val) {
        sb.append('"').append(key).append("\":").append(val);
    }

    private static void appendBool(StringBuilder sb, String key, boolean val) {
        sb.append('"').append(key).append("\":").append(val);
    }

    // -------------------------------------------------------------------------
    // Decode
    // -------------------------------------------------------------------------

    static PersonalityMode decodeMode(String json) {
        if (json == null || json.equals("null")) return null;
        try {
            PersonalityMode mode = new PersonalityMode();
            mode.id          = extractString(json, "id");
            mode.name        = extractString(json, "name");
            mode.description = extractString(json, "description");
            mode.tier        = extractInt(json,    "tier",    1);
            mode.isCustom    = extractBool(json,   "isCustom", true);

            int cfgStart = json.indexOf("\"config\":");
            if (cfgStart >= 0) {
                cfgStart = json.indexOf('{', cfgStart);
                int cfgEnd = findMatchingBrace(json, cfgStart);
                if (cfgEnd > cfgStart) {
                    mode.config = decodeConfig(json.substring(cfgStart, cfgEnd + 1));
                }
            }
            if (mode.config == null) mode.config = new ModeConfig();
            return mode;
        } catch (Exception e) {
            Log.e(TAG, "decodeMode failed: " + e.getMessage());
            return null;
        }
    }

    static List<PersonalityMode> decodeModeList(String json) {
        List<PersonalityMode> result = new ArrayList<>();
        if (json == null || json.isEmpty()) return result;
        // Strip outer array brackets
        json = json.trim();
        if (json.startsWith("[")) json = json.substring(1);
        if (json.endsWith("]"))   json = json.substring(0, json.length() - 1);
        json = json.trim();
        if (json.isEmpty()) return result;

        // Split on top-level object boundaries
        int depth = 0, start = 0;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') { if (depth == 0) start = i; depth++; }
            else if (c == '}') {
                depth--;
                if (depth == 0) {
                    PersonalityMode m = decodeMode(json.substring(start, i + 1));
                    if (m != null) result.add(m);
                }
            }
        }
        return result;
    }

    private static ModeConfig decodeConfig(String json) {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = extractBool(json, "dndEnabled",       false);
        cfg.notificationLevel = extractInt(json,  "notificationLevel", ModeConfig.NOTIF_ALL);
        cfg.wifiEnabled       = extractBool(json, "wifiEnabled",      true);
        cfg.dataEnabled       = extractBool(json, "dataEnabled",      true);
        cfg.locationEnabled   = extractBool(json, "locationEnabled",  true);
        cfg.bluetoothEnabled  = extractBool(json, "bluetoothEnabled", true);
        cfg.screenBrightness  = extractInt(json,  "screenBrightness", -1);
        cfg.themeMode         = extractInt(json,  "themeMode",        ModeConfig.THEME_AUTO);
        cfg.enforceVpn        = extractBool(json, "enforceVpn",       false);
        cfg.privacyLevel      = extractInt(json,  "privacyLevel",     ModeConfig.PRIVACY_NORMAL);
        cfg.cloudSyncEnabled  = extractBool(json, "cloudSyncEnabled", true);
        return cfg;
    }

    // -------------------------------------------------------------------------
    // Minimal JSON helpers — no regex, no external libs
    // -------------------------------------------------------------------------

    private static String extractString(String json, String key) {
        String search = "\"" + key + "\":\"";
        int idx = json.indexOf(search);
        if (idx < 0) return "";
        idx += search.length();
        int end = json.indexOf('"', idx);
        while (end > 0 && json.charAt(end - 1) == '\\') end = json.indexOf('"', end + 1);
        return end > idx ? json.substring(idx, end).replace("\\\"", "\"") : "";
    }

    private static int extractInt(String json, String key, int defaultVal) {
        String search = "\"" + key + "\":";
        int idx = json.indexOf(search);
        if (idx < 0) return defaultVal;
        idx += search.length();
        int end = idx;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        try { return Integer.parseInt(json.substring(idx, end)); }
        catch (NumberFormatException e) { return defaultVal; }
    }

    private static boolean extractBool(String json, String key, boolean defaultVal) {
        String search = "\"" + key + "\":";
        int idx = json.indexOf(search);
        if (idx < 0) return defaultVal;
        idx += search.length();
        if (json.startsWith("true",  idx)) return true;
        if (json.startsWith("false", idx)) return false;
        return defaultVal;
    }

    private static int findMatchingBrace(String s, int openIdx) {
        int depth = 0;
        for (int i = openIdx; i < s.length(); i++) {
            if (s.charAt(i) == '{') depth++;
            else if (s.charAt(i) == '}') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }
}
