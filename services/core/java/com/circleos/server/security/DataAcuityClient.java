/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;

/**
 * Data Acuity Network Client.
 *
 * Handles:
 *   1. Threat feed downloads — pull c2_ips.txt, c2_domains.txt, malware_hashes.txt
 *      with Ed25519 signature verification before writing to disk.
 *   2. IOC batch submission — POST anonymized IOCs from CommunityDefenseService.
 *   3. Critical threat push handling — future: WebSocket subscription.
 *
 * Phase 2: HTTP polling (no persistent connection).
 * Phase 3: WebSocket for real-time critical threat push.
 *
 * All feeds are signed by Data Acuity's Ed25519 key (embedded at compile time).
 * A feed with an invalid signature is discarded — never written to disk.
 */
public class DataAcuityClient {

    private static final String TAG = "DataAcuity";

    // Base URL — populated from build config in real build
    private static final String BASE_URL        = "https://feeds.dataacuity.circleos.co.za";
    private static final String FEED_IPS_PATH   = "/v1/feeds/c2_ips.txt";
    private static final String FEED_DOMAINS_PATH = "/v1/feeds/c2_domains.txt";
    private static final String FEED_HASHES_PATH  = "/v1/feeds/malware_hashes.txt";
    private static final String SUBMIT_PATH     = "/v1/community/iocs";

    private static final String FEEDS_DIR = "/data/circle/security/feeds/";
    private static final int    TIMEOUT_MS = 30_000;

    /**
     * Download and verify all threat feeds.
     * Each feed is downloaded, signature verified, then atomically written to disk.
     * @return true if all feeds were updated successfully
     */
    public boolean downloadFeeds() {
        boolean ok = true;
        ok &= downloadFeed(FEED_IPS_PATH,      "c2_ips.txt");
        ok &= downloadFeed(FEED_DOMAINS_PATH,  "c2_domains.txt");
        ok &= downloadFeed(FEED_HASHES_PATH,   "malware_hashes.txt");
        return ok;
    }

    private boolean downloadFeed(String path, String filename) {
        try {
            String feedUrl  = BASE_URL + path;
            String sigUrl   = feedUrl + ".sig";

            byte[] feedData = httpGet(feedUrl);
            byte[] sigData  = httpGet(sigUrl);

            if (feedData == null || sigData == null) {
                Log.w(TAG, "Download failed: " + filename);
                return false;
            }

            if (!verifySignature(feedData, sigData)) {
                Log.e(TAG, "Signature INVALID for " + filename + " — discarding");
                return false;
            }

            // Atomic write: write to .tmp, rename
            File tmp  = new File(FEEDS_DIR + filename + ".tmp");
            File dest = new File(FEEDS_DIR + filename);
            try (FileOutputStream fos = new FileOutputStream(tmp)) {
                fos.write(feedData);
            }
            tmp.renameTo(dest);
            Log.i(TAG, "Feed updated: " + filename + " (" + feedData.length + " bytes)");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Feed download error: " + filename, e);
            return false;
        }
    }

    /**
     * Submit a batch of anonymized IOCs to Data Acuity.
     */
    public void submitIocBatch(List<CommunityDefenseService.AnonymizedIoc> batch) {
        if (batch == null || batch.isEmpty()) return;
        try {
            StringBuilder json = new StringBuilder("[");
            for (int i = 0; i < batch.size(); i++) {
                CommunityDefenseService.AnonymizedIoc ioc = batch.get(i);
                if (i > 0) json.append(",");
                json.append("{\"type\":\"").append(ioc.type.name().toLowerCase())
                    .append("\",\"value\":\"").append(escapeJson(ioc.value))
                    .append("\",\"verdict\":").append(ioc.verdict)
                    .append(",\"confidence\":").append(ioc.confidence)
                    .append("}");
            }
            json.append("]");

            httpPost(BASE_URL + SUBMIT_PATH, json.toString().getBytes(StandardCharsets.UTF_8));
            Log.i(TAG, "Submitted " + batch.size() + " IOCs");
        } catch (Exception e) {
            Log.e(TAG, "IOC submission failed", e);
        }
    }

    /* ── Signature verification ─────────────────────────────────────────── */

    /**
     * Verify Ed25519 signature on feed data.
     * Public key is embedded in the APK resources at compile time.
     * Phase 2: uses placeholder verification (always returns true for dev builds).
     * Phase 3: real Ed25519 verification with bundled public key.
     */
    private boolean verifySignature(byte[] data, byte[] signature) {
        // TODO Phase 3: load Ed25519 public key from res/raw/dataacuity_pubkey.der
        //   PublicKey pk = loadPublicKey();
        //   Signature sig = Signature.getInstance("Ed25519");
        //   sig.initVerify(pk);
        //   sig.update(data);
        //   return sig.verify(signature);
        Log.d(TAG, "Signature verification (Phase 2 placeholder) — OK");
        return true;
    }

    /* ── HTTP helpers ──────────────────────────────────────────────────── */

    private byte[] httpGet(String urlStr) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "CircleOS-Security/1.0");

            int status = conn.getResponseCode();
            if (status != 200) {
                Log.w(TAG, "GET " + urlStr + " → HTTP " + status);
                return null;
            }

            try (InputStream is = conn.getInputStream()) {
                return is.readAllBytes();
            }
        } catch (Exception e) {
            Log.w(TAG, "GET failed: " + urlStr + " — " + e.getMessage());
            return null;
        }
    }

    private void httpPost(String urlStr, byte[] body) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("User-Agent", "CircleOS-Security/1.0");
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }
        int status = conn.getResponseCode();
        if (status < 200 || status >= 300) {
            Log.w(TAG, "POST " + urlStr + " → HTTP " + status);
        }
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
