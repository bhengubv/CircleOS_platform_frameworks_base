/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.util.Base64;
import android.util.Log;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import za.co.circleos.personality.PersonalityMode;

/**
 * Handles community mode sharing:
 *
 * <ul>
 *   <li><b>Export</b>: Encodes a single mode as a Base64-JSON URL.</li>
 *   <li><b>Import from URL</b>: Fetches and decodes a shared mode URL.</li>
 *   <li><b>Community store</b>: Fetches a curated list from the CircleOS mode store.</li>
 * </ul>
 *
 * URLs are of the form: {@code https://modes.circleos.za.co/share#<base64json>}
 */
class CommunityShareManager {

    private static final String TAG        = "CirclePersonality";
    private static final String SHARE_BASE = "https://modes.circleos.za.co/share#";
    private static final String STORE_URL  = "https://modes.circleos.za.co/store/modes.json";
    private static final int    TIMEOUT_MS = 15_000;

    // ---- Export -------------------------------------------------------------

    /**
     * Encodes a mode as a shareable URL.  The mode JSON is Base64url-encoded
     * and appended as the URL fragment so it never hits a server.
     *
     * @param mode the mode to share
     * @return a shareable URL string, or null on error
     */
    String getModeShareUrl(PersonalityMode mode) {
        if (mode == null) return null;
        try {
            String json = ModeSerializer.encodeMode(mode);
            String b64  = Base64.encodeToString(
                    json.getBytes(StandardCharsets.UTF_8),
                    Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            return SHARE_BASE + b64;
        } catch (Exception e) {
            Log.e(TAG, "getModeShareUrl failed: " + e.getMessage());
            return null;
        }
    }

    // ---- Import from URL ----------------------------------------------------

    /**
     * Imports a mode from a share URL or a direct HTTP(S) URL that returns
     * mode JSON.
     *
     * @param url the URL to fetch
     * @return decoded PersonalityMode, or null on failure
     */
    PersonalityMode importFromUrl(String url) {
        if (url == null || url.isEmpty()) return null;

        // Fragment-encoded share URL — decode inline without network call
        int fragIdx = url.indexOf('#');
        if (fragIdx >= 0 && url.startsWith(SHARE_BASE)) {
            String b64 = url.substring(fragIdx + 1);
            return decodeBase64Mode(b64);
        }

        // Remote JSON URL — fetch and decode
        try {
            String json = fetch(url);
            if (json == null || json.isEmpty()) return null;
            List<PersonalityMode> modes = ModeSerializer.decodeModeList(json);
            if (modes != null && !modes.isEmpty()) return modes.get(0);
            return ModeSerializer.decodeMode(json);
        } catch (Exception e) {
            Log.e(TAG, "importFromUrl failed: " + url + " — " + e.getMessage());
            return null;
        }
    }

    // ---- Community store ----------------------------------------------------

    /**
     * Fetches the curated community mode listing from the CircleOS mode store.
     *
     * @return list of community modes (empty list on failure)
     */
    List<PersonalityMode> fetchCommunityModes() {
        try {
            String json = fetch(STORE_URL);
            if (json == null || json.isEmpty()) return Collections.emptyList();
            List<PersonalityMode> modes = ModeSerializer.decodeModeList(json);
            return modes != null ? modes : Collections.emptyList();
        } catch (Exception e) {
            Log.e(TAG, "fetchCommunityModes failed: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    // ---- Helpers ------------------------------------------------------------

    private static PersonalityMode decodeBase64Mode(String b64) {
        try {
            byte[] bytes = Base64.decode(b64, Base64.URL_SAFE | Base64.NO_PADDING);
            String json  = new String(bytes, StandardCharsets.UTF_8);
            List<PersonalityMode> modes = ModeSerializer.decodeModeList(json);
            if (modes != null && !modes.isEmpty()) return modes.get(0);
            return ModeSerializer.decodeMode(json);
        } catch (Exception e) {
            Log.w(TAG, "decodeBase64Mode failed: " + e.getMessage());
            return null;
        }
    }

    private static String fetch(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        conn.setRequestProperty("Accept", "application/json");
        conn.connect();

        int code = conn.getResponseCode();
        if (code != 200) {
            Log.w(TAG, "fetch HTTP " + code + " for " + urlStr);
            return null;
        }

        try (InputStream in    = conn.getInputStream();
             BufferedReader br = new BufferedReader(
                     new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        } finally {
            conn.disconnect();
        }
    }
}
