/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.util.Log;
import java.io.*;
import java.util.*;

/**
 * Persists the set of downloaded bundle IDs to
 * /data/system/circle/personality/bundles.json
 */
class BundleStateStore {
    private static final String TAG  = "CirclePersonality";
    private static final String PATH = "/data/system/circle/personality/bundles.json";

    private final Set<String> mDownloaded = new HashSet<>();
    private final File mFile = new File(PATH);

    void init() {
        if (!mFile.exists()) return;
        try (BufferedReader br = new BufferedReader(new FileReader(mFile))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            String json = sb.toString().trim();
            // Format: ["bundleId1","bundleId2"]
            if (json.startsWith("[")) json = json.substring(1);
            if (json.endsWith("]"))   json = json.substring(0, json.length()-1);
            for (String part : json.split(",")) {
                String id = part.trim().replace("\"", "");
                if (!id.isEmpty()) mDownloaded.add(id);
            }
        } catch (IOException e) {
            Log.e(TAG, "BundleStateStore load failed: " + e.getMessage());
        }
    }

    void markDownloaded(String bundleId) {
        mDownloaded.add(bundleId);
        save();
    }

    boolean isDownloaded(String bundleId) {
        return mDownloaded.contains(bundleId);
    }

    Set<String> getDownloadedBundles() {
        return Collections.unmodifiableSet(mDownloaded);
    }

    private void save() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String id : mDownloaded) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(id).append('"');
        }
        sb.append(']');
        try (FileWriter fw = new FileWriter(mFile, false)) {
            fw.write(sb.toString());
        } catch (IOException e) {
            Log.e(TAG, "BundleStateStore save failed: " + e.getMessage());
        }
    }
}
