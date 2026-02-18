/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.inference;

import android.util.Log;

import za.co.circleos.inference.ModelInfo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages model discovery, integrity verification, and downloads (Phase 2).
 *
 * Bundled:    /system/circle/models/   (read-only, ships with OS)
 * Downloaded: /data/circle/models/     (read-write, user-installed)
 *
 * manifest.json schema per directory:
 * { "models": [{ "id", "name", "filename", "parameterCount", "sizeBytes",
 *                "minRamMb", "recommendedTier", "backend",
 *                "downloadUrl", "sha256" }] }
 */
public class ModelManager {

    private static final String TAG = "CircleInference.ModelMgr";
    private static final String BUNDLED_DIR  = "/system/circle/models/";
    private static final String DOWNLOAD_DIR = "/data/circle/models/";
    private static final String MANIFEST     = "manifest.json";

    /** Callback for download progress events. */
    public interface DownloadCallback {
        void onProgress(String modelId, long bytesReceived, long totalBytes);
        void onComplete(String modelId);
        void onError(String modelId, String message);
    }

    public ModelManager() {}

    // ── Discovery ─────────────────────────────────────────────────────────────

    public List<ModelInfo> listAvailableModels() {
        List<ModelInfo> models = new ArrayList<>();
        scan(new File(BUNDLED_DIR),  true,  models);
        scan(new File(DOWNLOAD_DIR), false, models);
        Log.i(TAG, "Found " + models.size() + " model(s)");
        return models;
    }

    private void scan(File dir, boolean bundled, List<ModelInfo> out) {
        if (!dir.isDirectory()) return;
        File manifest = new File(dir, MANIFEST);
        if (!manifest.exists()) return;
        try {
            JSONArray arr = new JSONObject(readFile(manifest)).getJSONArray("models");
            for (int i = 0; i < arr.length(); i++) {
                out.add(parseModel(arr.getJSONObject(i), dir, bundled));
            }
        } catch (Exception e) {
            Log.e(TAG, "Manifest parse error in " + dir, e);
        }
    }

    private ModelInfo parseModel(JSONObject o, File dir, boolean bundled) throws Exception {
        ModelInfo m = new ModelInfo();
        m.id              = o.optString("id", "unknown");
        m.name            = o.optString("name", m.id);
        m.parameterCount  = o.optLong("parameterCount", 0);
        m.sizeBytes       = o.optLong("sizeBytes", 0);
        m.minRamMb        = o.optInt("minRamMb", 0);
        m.recommendedTier = o.optInt("recommendedTier", 1);
        m.backend         = o.optString("backend", "llama.cpp");
        m.isBundled       = bundled;
        String fn = o.optString("filename", "");
        m.isDownloaded    = !fn.isEmpty() && new File(dir, fn).exists();
        return m;
    }

    // ── Selection ─────────────────────────────────────────────────────────────

    public ModelInfo selectOptimalModel(int tier) {
        ModelInfo best = null;
        for (ModelInfo m : listAvailableModels()) {
            if (!m.isDownloaded && !m.isBundled) continue;
            if (m.recommendedTier <= tier &&
                    (best == null || m.recommendedTier > best.recommendedTier)) {
                best = m;
            }
        }
        if (best != null) Log.i(TAG, "Selected: " + best.id + " (tier " + best.recommendedTier + ")");
        else Log.w(TAG, "No model for tier " + tier);
        return best;
    }

    // ── Lookups ───────────────────────────────────────────────────────────────

    public String getModelPath(String modelId) { return lookup(modelId, "filename"); }
    public String getExpectedChecksum(String modelId) { return lookup(modelId, "sha256"); }
    public String getDownloadUrl(String modelId) { return lookup(modelId, "downloadUrl"); }

    private String lookup(String modelId, String field) {
        for (File dir : new File[]{new File(BUNDLED_DIR), new File(DOWNLOAD_DIR)}) {
            File mf = new File(dir, MANIFEST);
            if (!mf.exists()) continue;
            try {
                JSONArray arr = new JSONObject(readFile(mf)).getJSONArray("models");
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject o = arr.getJSONObject(i);
                    if (!modelId.equals(o.optString("id"))) continue;
                    if ("filename".equals(field)) {
                        String fn = o.optString("filename", "");
                        File f = new File(dir, fn);
                        return (fn.isEmpty() || !f.exists()) ? null : f.getAbsolutePath();
                    }
                    String v = o.optString(field, "");
                    return v.isEmpty() ? null : v;
                }
            } catch (Exception e) {
                Log.e(TAG, "Lookup error for " + field, e);
            }
        }
        return null;
    }

    // ── Integrity ─────────────────────────────────────────────────────────────

    public boolean verifyIntegrity(File file, String expected) {
        if (expected == null || expected.isEmpty()) return true;
        try {
            boolean ok = sha256(file).equalsIgnoreCase(expected);
            if (!ok) Log.e(TAG, "Integrity FAILED: " + file.getName());
            return ok;
        } catch (Exception e) {
            Log.e(TAG, "Integrity check error", e);
            return false;
        }
    }

    // ── Remote manifest (Phase 4) ─────────────────────────────────────────────

    /**
     * Fetches the remote model store manifest and returns the list of available
     * models. Merges with locally-installed models: remote entries with a
     * matching model_id inherit isDownloaded = true if the file is present.
     *
     * Expected JSON shape (from SleptOnAPI GET /inference/models):
     * { "models": [{ "modelId", "name", "filename", "quantization",
     *                "sizeBytes", "sha256", "cdnUrl", "minRamMb",
     *                "parameterCount", "recommendedTier", "backend" }] }
     *
     * @param manifestUrl  Full URL to the manifest endpoint
     * @return list of remote ModelInfo objects, empty on network/parse failure
     */
    public List<ModelInfo> fetchRemoteManifest(String manifestUrl) {
        List<ModelInfo> result = new ArrayList<>();
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(manifestUrl).openConnection();
            conn.setConnectTimeout(15_000);
            conn.setReadTimeout(20_000);
            conn.setRequestProperty("Accept", "application/json");
            conn.connect();
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "Remote manifest returned HTTP " + conn.getResponseCode());
                return result;
            }
            StringBuilder sb = new StringBuilder();
            try (java.io.InputStream is = new BufferedInputStream(conn.getInputStream());
                 java.io.InputStreamReader isr = new java.io.InputStreamReader(is);
                 BufferedReader br = new BufferedReader(isr)) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
            }
            JSONArray arr = new JSONObject(sb.toString()).getJSONArray("models");
            File downloadDir = new File(DOWNLOAD_DIR);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                ModelInfo m = new ModelInfo();
                m.id              = o.optString("modelId", "unknown");
                m.name            = o.optString("name", m.id);
                m.sizeBytes       = o.optLong("sizeBytes", 0);
                m.parameterCount  = o.optLong("parameterCount", 0);
                m.minRamMb        = o.optInt("minRamMb", 0);
                m.recommendedTier = o.optInt("recommendedTier", 1);
                m.backend         = o.optString("backend", "llama.cpp");
                m.isBundled       = false;
                String fn         = o.optString("filename", "");
                m.isDownloaded    = !fn.isEmpty() && new File(downloadDir, fn).exists();
                result.add(m);
                // Stash CDN URL + SHA256 for use by downloadModel()
                String cdnUrl = o.optString("cdnUrl", "");
                if (!cdnUrl.isEmpty()) _remoteCdnUrls.put(m.id, cdnUrl);
                String sha256 = o.optString("sha256", "");
                if (!sha256.isEmpty()) _remoteSha256s.put(m.id, sha256);
            }
            Log.i(TAG, "Remote manifest: " + result.size() + " model(s) from " + manifestUrl);
        } catch (Exception e) {
            Log.w(TAG, "Failed to fetch remote manifest: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
        return result;
    }

    /**
     * Refreshes the in-memory remote manifest cache. Should be called once after
     * boot from a background thread. Subsequent listRemoteModels() calls are fast.
     */
    public synchronized void refreshRemoteManifest(String manifestUrl) {
        try {
            List<ModelInfo> remote = fetchRemoteManifest(manifestUrl);
            if (!remote.isEmpty()) {
                _remoteManifestUrl  = manifestUrl;
                _remoteModels       = remote;
                _remoteRefreshedAt  = System.currentTimeMillis();
                Log.i(TAG, "Remote manifest cached: " + remote.size() + " model(s)");
            }
        } catch (Exception e) {
            Log.w(TAG, "refreshRemoteManifest failed", e);
        }
    }

    /** Returns the last cached remote model list, or empty if never fetched. */
    public synchronized List<ModelInfo> getCachedRemoteModels() {
        return _remoteModels != null ? _remoteModels : new ArrayList<>();
    }

    // Remote manifest cache — populated by refreshRemoteManifest()
    private volatile String          _remoteManifestUrl;
    private volatile List<ModelInfo> _remoteModels;
    private volatile long            _remoteRefreshedAt;
    // Per-model CDN URL and SHA256 from last successful remote fetch
    private final Map<String, String> _remoteCdnUrls  = new HashMap<>();
    private final Map<String, String> _remoteSha256s  = new HashMap<>();

    // ── Download (Phase 2 / Phase 4) ──────────────────────────────────────────

    /**
     * Downloads a model to /data/circle/models/.
     * Prefers a cached remote CDN URL if the model was found via fetchRemoteManifest;
     * falls back to the local manifest downloadUrl field.
     * Call from a background thread.
     */
    public void downloadModel(String modelId, DownloadCallback cb) {
        // Prefer remote CDN URL; fall back to local manifest downloadUrl
        String url = _remoteCdnUrls.get(modelId);
        if (url == null) url = getDownloadUrl(modelId);
        if (url == null) {
            String msg = "No downloadUrl for: " + modelId;
            Log.e(TAG, msg);
            if (cb != null) cb.onError(modelId, msg);
            return;
        }
        new File(DOWNLOAD_DIR).mkdirs();
        String fn = url.substring(url.lastIndexOf('/') + 1);
        if (fn.isEmpty()) fn = modelId + ".gguf";
        File dest = new File(DOWNLOAD_DIR, fn);
        Log.i(TAG, "Downloading " + modelId + " from " + url);
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(30_000);
            conn.setReadTimeout(60_000);
            conn.connect();
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + conn.getResponseCode());
            }
            long total = conn.getContentLengthLong(), received = 0;
            try (InputStream in = new BufferedInputStream(conn.getInputStream());
                 FileOutputStream out = new FileOutputStream(dest)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    received += n;
                    if (cb != null) cb.onProgress(modelId, received, total);
                }
            }
            // Verify SHA256 from remote manifest (or local manifest fallback)
            String expectedSha = _remoteSha256s.containsKey(modelId)
                    ? _remoteSha256s.get(modelId)
                    : getExpectedChecksum(modelId);
            if (expectedSha != null && !verifyIntegrity(dest, expectedSha)) {
                dest.delete();
                String msg = "Integrity check failed after download: " + modelId;
                Log.e(TAG, msg);
                if (cb != null) cb.onError(modelId, msg);
                return;
            }
            Log.i(TAG, "Download complete: " + dest);
            if (cb != null) cb.onComplete(modelId);
        } catch (IOException e) {
            Log.e(TAG, "Download failed: " + modelId, e);
            dest.delete();
            if (cb != null) cb.onError(modelId, e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String sha256(File f) throws IOException, NoSuchAlgorithmException {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] buf = new byte[65536]; int n;
            while ((n = fis.read(buf)) > 0) d.update(buf, 0, n);
        }
        StringBuilder sb = new StringBuilder(64);
        for (byte b : d.digest()) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String readFile(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            String line; while ((line = r.readLine()) != null) sb.append(line).append('\n');
        }
        return sb.toString();
    }
}
