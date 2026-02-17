/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.os.RemoteException;
import android.util.ArrayMap;
import android.util.Log;

import java.io.*;
import java.net.*;
import java.util.*;

import za.co.circleos.personality.IBundleCallback;
import za.co.circleos.personality.ModeBundle;

/**
 * Manages Tier-2 lifestyle mode bundle downloads.
 *
 * Download flow:
 * 1. Client calls {@link #downloadBundle} with a modeId + callback.
 * 2. Manager starts a background thread that performs HTTP GET.
 * 3. Progress is reported via {@link IBundleCallback#onProgress} every 5%.
 * 4. On success, bundle is marked downloaded in {@link BundleStateStore}.
 * 5. {@link IBundleCallback#onComplete} fires with success=true.
 */
class BundleDownloadManager {

    private static final String TAG      = "CirclePersonality";
    private static final String BUNDLE_DIR = "/data/system/circle/personality/bundles/";

    private final Map<String, ModeBundle>       mBundles   = new ArrayMap<>();
    private final Map<String, IBundleCallback>  mCallbacks = new ArrayMap<>();
    private final Map<String, Thread>           mThreads   = new ArrayMap<>();
    private final BundleStateStore              mStore;

    BundleDownloadManager(BundleStateStore store) {
        mStore = store;
        for (ModeBundle b : Tier2Modes.allBundles()) {
            mBundles.put(b.modeId, b);
        }
        // Mark bundles already recorded in store as downloaded
        for (ModeBundle b : mBundles.values()) {
            b.isDownloaded = mStore.isDownloaded(b.bundleId);
        }
        Log.d(TAG, "BundleDownloadManager: " + mBundles.size() + " bundles registered");
    }

    ModeBundle getBundleInfo(String modeId) {
        ModeBundle b = mBundles.get(modeId);
        if (b != null) b.isDownloaded = mStore.isDownloaded(b.bundleId);
        return b;
    }

    List<ModeBundle> getAvailableBundles() {
        for (ModeBundle b : mBundles.values()) {
            b.isDownloaded = mStore.isDownloaded(b.bundleId);
        }
        return new ArrayList<>(mBundles.values());
    }

    boolean isBundleDownloaded(String modeId) {
        ModeBundle b = mBundles.get(modeId);
        return b != null && mStore.isDownloaded(b.bundleId);
    }

    List<String> getBundleApps(String modeId) {
        ModeBundle b = mBundles.get(modeId);
        if (b == null) return Collections.emptyList();
        List<String> all = new ArrayList<>(b.requiredApps);
        all.addAll(b.recommendedApps);
        return all;
    }

    void downloadBundle(String modeId, IBundleCallback callback) {
        ModeBundle b = mBundles.get(modeId);
        if (b == null) {
            notifyError(callback, modeId, "Unknown bundle: " + modeId);
            return;
        }

        if (mStore.isDownloaded(b.bundleId)) {
            notifyComplete(callback, modeId, true, null);
            return;
        }

        synchronized (mThreads) {
            if (mThreads.containsKey(modeId)) {
                Log.d(TAG, "Download already in progress for " + modeId);
                return;
            }
            mCallbacks.put(modeId, callback);
            Thread t = new Thread(() -> performDownload(b, callback), "BundleDL-" + modeId);
            mThreads.put(modeId, t);
            t.start();
        }
    }

    void cancelBundleDownload(String modeId) {
        synchronized (mThreads) {
            Thread t = mThreads.get(modeId);
            if (t != null) {
                t.interrupt();
                mThreads.remove(modeId);
                mCallbacks.remove(modeId);
                Log.i(TAG, "Bundle download cancelled: " + modeId);
            }
        }
    }

    private void performDownload(ModeBundle bundle, IBundleCallback callback) {
        String modeId = bundle.modeId;
        File dir = new File(BUNDLE_DIR + modeId);
        dir.mkdirs();
        File outFile = new File(dir, "bundle.json");

        try {
            URL url = new URL(bundle.downloadUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(15_000);
            conn.setReadTimeout(60_000);
            conn.connect();

            long total = bundle.sizeBytes > 0 ? bundle.sizeBytes
                    : conn.getContentLengthLong();
            if (total <= 0) total = 1;

            int lastPct = -1;
            long received = 0;

            try (InputStream in = conn.getInputStream();
                 FileOutputStream out = new FileOutputStream(outFile)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    if (Thread.interrupted()) throw new InterruptedException("cancelled");
                    out.write(buf, 0, n);
                    received += n;
                    int pct = (int) Math.min(99, (received * 100) / total);
                    if (pct >= lastPct + 5) {
                        lastPct = pct;
                        notifyProgress(callback, modeId, pct);
                    }
                }
            } finally {
                conn.disconnect();
            }

            mStore.markDownloaded(bundle.bundleId);
            bundle.isDownloaded    = true;
            bundle.downloadProgress = 100;
            bundle.localPath        = outFile.getAbsolutePath();
            notifyProgress(callback, modeId, 100);
            notifyComplete(callback, modeId, true, null);
            Log.i(TAG, "Bundle downloaded: " + modeId);

        } catch (InterruptedException e) {
            Log.i(TAG, "Bundle download interrupted: " + modeId);
            outFile.delete();
        } catch (Exception e) {
            Log.e(TAG, "Bundle download failed: " + modeId + " — " + e.getMessage());
            outFile.delete();
            notifyComplete(callback, modeId, false, e.getMessage());
        } finally {
            synchronized (mThreads) {
                mThreads.remove(modeId);
                mCallbacks.remove(modeId);
            }
        }
    }

    private void notifyProgress(IBundleCallback cb, String modeId, int pct) {
        try { if (cb != null) cb.onProgress(modeId, pct); }
        catch (RemoteException ignored) {}
    }

    private void notifyComplete(IBundleCallback cb, String modeId, boolean ok, String err) {
        try { if (cb != null) cb.onComplete(modeId, ok, err); }
        catch (RemoteException ignored) {}
    }

    private void notifyError(IBundleCallback cb, String modeId, String msg) {
        notifyComplete(cb, modeId, false, msg);
    }
}
