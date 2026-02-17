/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import za.co.circleos.personality.PersonalityMode;

/**
 * Persists custom (user-created) personality modes and per-mode hidden app lists
 * to JSON files under {@code /data/system/circle/personality/}.
 */
class CustomModeStore {

    private static final String TAG       = "CirclePersonality";
    private static final String DIR_PATH  = "/data/system/circle/personality";
    private static final String MODES_FILE     = DIR_PATH + "/modes.json";
    private static final String APP_RULES_FILE = DIR_PATH + "/app_rules.json";

    private final File mModesFile;
    private final File mAppRulesFile;

    CustomModeStore() {
        mModesFile    = new File(MODES_FILE);
        mAppRulesFile = new File(APP_RULES_FILE);
    }

    /** Creates the storage directory if needed. */
    void init() {
        File dir = new File(DIR_PATH);
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                Log.w(TAG, "Could not create personality store dir: " + DIR_PATH);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Custom mode persistence
    // -------------------------------------------------------------------------

    List<PersonalityMode> loadCustomModes() {
        if (!mModesFile.exists()) return new ArrayList<>();
        String json = readFile(mModesFile);
        if (json == null || json.isEmpty()) return new ArrayList<>();
        return ModeSerializer.decodeModeList(json);
    }

    void saveCustomModes(List<PersonalityMode> modes) {
        // Only persist custom modes
        List<PersonalityMode> custom = new ArrayList<>();
        for (PersonalityMode m : modes) {
            if (m.isCustom) custom.add(m);
        }
        writeFile(mModesFile, ModeSerializer.encodeModeList(custom));
    }

    // -------------------------------------------------------------------------
    // App rules persistence  (modeId → list of hidden package names)
    // -------------------------------------------------------------------------

    Map<String, List<String>> loadAppRules() {
        Map<String, List<String>> result = new HashMap<>();
        if (!mAppRulesFile.exists()) return result;
        String json = readFile(mAppRulesFile);
        if (json == null || json.isEmpty()) return result;
        // Simple format: {"modeId":["pkg1","pkg2"],...}
        try {
            json = json.trim();
            if (json.startsWith("{")) json = json.substring(1);
            if (json.endsWith("}"))   json = json.substring(0, json.length() - 1);
            // Split by top-level keys
            int i = 0;
            while (i < json.length()) {
                int keyStart = json.indexOf('"', i);
                if (keyStart < 0) break;
                int keyEnd = json.indexOf('"', keyStart + 1);
                if (keyEnd < 0) break;
                String key = json.substring(keyStart + 1, keyEnd);
                int arrStart = json.indexOf('[', keyEnd);
                if (arrStart < 0) break;
                int arrEnd = json.indexOf(']', arrStart);
                if (arrEnd < 0) break;
                String arrContent = json.substring(arrStart + 1, arrEnd).trim();
                List<String> pkgs = new ArrayList<>();
                if (!arrContent.isEmpty()) {
                    for (String part : arrContent.split(",")) {
                        String pkg = part.trim().replace("\"", "");
                        if (!pkg.isEmpty()) pkgs.add(pkg);
                    }
                }
                result.put(key, pkgs);
                i = arrEnd + 1;
            }
        } catch (Exception e) {
            Log.e(TAG, "loadAppRules parse error: " + e.getMessage());
        }
        return result;
    }

    void saveAppRules(Map<String, List<String>> rules) {
        StringBuilder sb = new StringBuilder('{');
        boolean first = true;
        for (Map.Entry<String, List<String>> entry : rules.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(entry.getKey()).append("\":[");
            List<String> pkgs = entry.getValue();
            for (int i = 0; i < pkgs.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(pkgs.get(i)).append('"');
            }
            sb.append(']');
        }
        sb.append('}');
        writeFile(mAppRulesFile, sb.toString());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String readFile(File f) {
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        } catch (IOException e) {
            Log.e(TAG, "readFile " + f.getName() + " failed: " + e.getMessage());
            return null;
        }
    }

    private void writeFile(File f, String content) {
        try (FileWriter fw = new FileWriter(f, false)) {
            fw.write(content);
        } catch (IOException e) {
            Log.e(TAG, "writeFile " + f.getName() + " failed: " + e.getMessage());
        }
    }
}
