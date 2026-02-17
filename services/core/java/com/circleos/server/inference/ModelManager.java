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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages model discovery, metadata parsing, integrity verification, and selection.
 *
 * Model directories:
 *   /system/circle/models/  — bundled, read-only
 *   /data/circle/models/    — user-downloaded, read-write
 *
 * Each directory may contain a manifest.json describing available models:
 * {
 *   "models": [
 *     {
 *       "id": "qwen-1.5b-q4",
 *       "name": "Qwen 1.5B Q4_K_M",
 *       "parameterCount": 1500000000,
 *       "sizeBytes": 987654321,
 *       "minRamMb": 2048,
 *       "recommendedTier": 2,
 *       "backend": "llama.cpp",
 *       "filename": "qwen-1.5b-q4_k_m.gguf",
 *       "sha256": "abcdef1234567890..."
 *     }
 *   ]
 * }
 */
public class ModelManager {

    private static final String TAG = "CircleInference.ModelMgr";

    private static final String BUNDLED_MODEL_DIR  = "/system/circle/models/";
    private static final String DOWNLOAD_MODEL_DIR = "/data/circle/models/";
    private static final String MANIFEST_FILENAME  = "manifest.json";

    public ModelManager() {}

    /**
     * Scans all model directories and returns metadata for all discovered models.
     */
    public List<ModelInfo> listAvailableModels() {
        List<ModelInfo> models = new ArrayList<>();
        scanDirectory(new File(BUNDLED_MODEL_DIR), true, models);
        scanDirectory(new File(DOWNLOAD_MODEL_DIR), false, models);
        Log.i(TAG, "Found " + models.size() + " model(s)");
        return models;
    }

    private void scanDirectory(File dir, boolean isBundled, List<ModelInfo> out) {
        if (!dir.exists() || !dir.isDirectory()) {
            Log.d(TAG, "Model directory not present: " + dir.getAbsolutePath());
            return;
        }

        File manifest = new File(dir, MANIFEST_FILENAME);
        if (!manifest.exists()) {
            Log.w(TAG, "No manifest.json in " + dir.getAbsolutePath());
            return;
        }

        try {
            String json = readFile(manifest);
            JSONObject root = new JSONObject(json);
            JSONArray arr = root.getJSONArray("models");
            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                ModelInfo info = parseModelInfo(obj, dir, isBundled);
                out.add(info);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse manifest in " + dir.getAbsolutePath(), e);
        }
    }

    private ModelInfo parseModelInfo(JSONObject obj, File dir, boolean isBundled) throws Exception {
        ModelInfo info = new ModelInfo();
        info.id             = obj.optString("id", "unknown");
        info.name           = obj.optString("name", info.id);
        info.parameterCount = obj.optLong("parameterCount", 0);
        info.sizeBytes      = obj.optLong("sizeBytes", 0);
        info.minRamMb       = obj.optInt("minRamMb", 0);
        info.recommendedTier = obj.optInt("recommendedTier", 1);
        info.backend        = obj.optString("backend", "llama.cpp");
        info.isBundled      = isBundled;

        String filename = obj.optString("filename", "");
        if (!filename.isEmpty()) {
            File modelFile = new File(dir, filename);
            info.isDownloaded = modelFile.exists();
        }

        return info;
    }

    /**
     * Selects the best available model for the given device tier.
     * Prefers models whose recommendedTier matches exactly; falls back to lower tiers.
     * Returns null if no suitable model is found.
     */
    public ModelInfo selectOptimalModel(int tier) {
        List<ModelInfo> all = listAvailableModels();
        ModelInfo best = null;

        for (ModelInfo m : all) {
            if (!m.isDownloaded && !m.isBundled) continue;
            if (m.recommendedTier <= tier) {
                if (best == null || m.recommendedTier > best.recommendedTier) {
                    best = m;
                }
            }
        }

        if (best != null) {
            Log.i(TAG, "Selected model: " + best.id + " (tier " + best.recommendedTier + ")");
        } else {
            Log.w(TAG, "No suitable model found for tier " + tier);
        }
        return best;
    }

    /**
     * Returns the absolute path of a model file given its ID.
     * Returns null if the model is not found or not downloaded.
     */
    public String getModelPath(String modelId) {
        for (File dir : new File[]{new File(BUNDLED_MODEL_DIR), new File(DOWNLOAD_MODEL_DIR)}) {
            File manifest = new File(dir, MANIFEST_FILENAME);
            if (!manifest.exists()) continue;
            try {
                String json = readFile(manifest);
                JSONObject root = new JSONObject(json);
                JSONArray arr = root.getJSONArray("models");
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject obj = arr.getJSONObject(i);
                    if (modelId.equals(obj.optString("id"))) {
                        String filename = obj.optString("filename", "");
                        if (!filename.isEmpty()) {
                            File f = new File(dir, filename);
                            if (f.exists()) return f.getAbsolutePath();
                        }
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Error searching manifest", e);
            }
        }
        return null;
    }

    /**
     * Returns the expected SHA-256 checksum for a model ID from its manifest.
     * Returns null if not specified.
     */
    public String getExpectedChecksum(String modelId) {
        for (File dir : new File[]{new File(BUNDLED_MODEL_DIR), new File(DOWNLOAD_MODEL_DIR)}) {
            File manifest = new File(dir, MANIFEST_FILENAME);
            if (!manifest.exists()) continue;
            try {
                String json = readFile(manifest);
                JSONObject root = new JSONObject(json);
                JSONArray arr = root.getJSONArray("models");
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject obj = arr.getJSONObject(i);
                    if (modelId.equals(obj.optString("id"))) {
                        String sha = obj.optString("sha256", "");
                        return sha.isEmpty() ? null : sha;
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Error reading checksum from manifest", e);
            }
        }
        return null;
    }

    /**
     * Verifies the SHA-256 integrity of a model file.
     * Returns true if the hash matches or if expectedSha256 is null/empty.
     */
    public boolean verifyIntegrity(File modelFile, String expectedSha256) {
        if (expectedSha256 == null || expectedSha256.isEmpty()) {
            Log.w(TAG, "No checksum to verify for " + modelFile.getName());
            return true;
        }
        try {
            String actual = sha256(modelFile);
            boolean ok = actual.equalsIgnoreCase(expectedSha256);
            if (!ok) {
                Log.e(TAG, "Integrity FAILED for " + modelFile.getName()
                        + " expected=" + expectedSha256 + " got=" + actual);
            }
            return ok;
        } catch (Exception e) {
            Log.e(TAG, "Integrity check error for " + modelFile.getName(), e);
            return false;
        }
    }

    private String sha256(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) > 0) {
                digest.update(buf, 0, n);
            }
        }
        byte[] hash = digest.digest();
        StringBuilder sb = new StringBuilder(64);
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String readFile(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }
}
