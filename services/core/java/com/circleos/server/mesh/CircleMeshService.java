/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Slog;

import com.android.server.LocalServices;
import com.android.server.SystemService;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * CircleOS Mesh OTA Delivery Service (Phase 4).
 *
 * Internal system service that coordinates P2P chunk acquisition for OTA
 * updates using WiFi Direct, mDNS (same-LAN WiFi), and Bluetooth LE.
 *
 * This service has no public Binder interface. It is invoked directly by
 * CircleUpdateService via {@link LocalServices}.
 *
 * Lifecycle:
 *   SystemServer → Lifecycle.onStart() (no-op for Binder)
 *   SystemServer → Lifecycle.onBootPhase(PHASE_BOOT_COMPLETED)
 *                → CircleMeshService.onBootCompleted()
 *                → LocalServices.addService(CircleMeshService.class, this)
 *
 * Download flow:
 *   1. Create ChunkManager with the update manifest.
 *   2. Start ChunkServer so we immediately serve any pre-held chunks.
 *   3. Start PeerDiscovery for the target version.
 *   4. Worker loop: for each missing chunk, try each known peer first
 *      (ChunkClient), then fall back to CDN HTTP range request.
 *   5. When all chunks are present, assemble and call onComplete().
 *   6. Progress callback every PROGRESS_INTERVAL chunks acquired.
 */
public final class CircleMeshService extends SystemService {

    private static final String TAG = "CircleMeshService";

    /** Service name used with LocalServices (not publishBinderService). */
    public static final String SERVICE_NAME = "circle.mesh";

    /** Report progress every N chunks acquired. */
    private static final int PROGRESS_INTERVAL = 5;

    /** CDN base URL for fallback HTTP chunk downloads. */
    private static final String CDN_BASE_URL = "https://updates.circleos.org/chunks/";

    /** HTTP connect timeout for CDN fallback (ms). */
    private static final int CDN_CONNECT_TIMEOUT_MS = 15_000;
    /** HTTP read timeout for CDN fallback (ms). */
    private static final int CDN_READ_TIMEOUT_MS    = 60_000;

    // -------------------------------------------------------------------------
    // Lifecycle inner class
    // -------------------------------------------------------------------------

    /**
     * Standard SystemService Lifecycle shim registered in SystemServer.
     *
     * CircleMeshService has no Binder — it is accessed via LocalServices by
     * other Circle system services (primarily CircleUpdateService).
     */
    public static class Lifecycle extends SystemService {
        private final CircleMeshService mService;

        public Lifecycle(Context context) {
            super(context);
            mService = new CircleMeshService(context);
        }

        @Override
        public void onStart() {
            // No Binder to publish — LocalServices registration happens at boot.
            Slog.i(TAG, "CircleMeshService.Lifecycle.onStart (no binder)");
        }

        @Override
        public void onBootPhase(int phase) {
            if (phase == PHASE_BOOT_COMPLETED) {
                mService.onBootCompleted();
            }
        }
    }

    // -------------------------------------------------------------------------
    // Public callback interface
    // -------------------------------------------------------------------------

    /**
     * Callback delivered to the caller of {@link #startMeshDownload}.
     */
    public interface MeshDownloadCallback {
        /** Called when all chunks have been assembled into a verified zip. */
        void onComplete(File assembledFile);
        /** Called when the download cannot be completed. */
        void onFailed(String reason);
        /** Called periodically as chunks are acquired. */
        void onProgress(int chunksHave, int chunksTotal);
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private final HandlerThread   mThread;
    private final Handler         mHandler;

    private final AtomicBoolean   mDownloadRunning = new AtomicBoolean(false);

    // Components for the active download session — null when idle.
    private volatile ChunkManager   mChunkManager;
    private volatile ChunkServer    mChunkServer;
    private volatile PeerDiscovery  mPeerDiscovery;
    private volatile MeshDownloadCallback mCallback;
    private volatile File           mDestFile;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public CircleMeshService(Context context) {
        super(context);
        mThread = new HandlerThread("CircleMesh");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());
    }

    // -------------------------------------------------------------------------
    // SystemService overrides
    // -------------------------------------------------------------------------

    @Override
    public void onStart() {
        // Not called directly; the Lifecycle shim manages this.
    }

    // -------------------------------------------------------------------------
    // Boot-completed initialisation
    // -------------------------------------------------------------------------

    /**
     * Called by {@link Lifecycle} when the system has fully booted.
     * Registers this service with LocalServices so CircleUpdateService can
     * retrieve it without a Binder round-trip.
     */
    void onBootCompleted() {
        LocalServices.addService(CircleMeshService.class, this);
        Slog.i(TAG, "CircleMeshService registered with LocalServices");
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Begins a mesh-assisted OTA chunk download.
     *
     * If a download is already in progress it is stopped before starting the
     * new one.
     *
     * @param version      OTA version string (e.g. "1.2.3-alpha").
     * @param manifestJson Chunk manifest JSON from the update server.
     * @param destFile     Destination file for the assembled OTA zip (the file
     *                     will be created/overwritten by ChunkManager).
     * @param callback     Progress and completion notifications.
     */
    public void startMeshDownload(String version, String manifestJson,
            File destFile, MeshDownloadCallback callback) {
        Slog.i(TAG, "startMeshDownload: version=" + version);
        stopMeshDownload(); // Stop any previous session

        mCallback  = callback;
        mDestFile  = destFile;
        mDownloadRunning.set(true);

        mHandler.post(() -> runDownload(version, manifestJson));
    }

    /**
     * Stops any in-progress mesh download and tears down all associated
     * resources.
     */
    public void stopMeshDownload() {
        if (!mDownloadRunning.compareAndSet(true, false)) return;

        Slog.i(TAG, "stopMeshDownload");

        mHandler.post(() -> {
            if (mPeerDiscovery != null) {
                mPeerDiscovery.stopDiscovery();
                mPeerDiscovery = null;
            }
            if (mChunkServer != null) {
                mChunkServer.stop();
                mChunkServer = null;
            }
            mChunkManager = null;
            mCallback      = null;
        });
    }

    // -------------------------------------------------------------------------
    // Download orchestration
    // -------------------------------------------------------------------------

    /**
     * Main download worker, runs on the CircleMesh HandlerThread.
     *
     * Steps:
     *   1. Create ChunkManager.
     *   2. Start ChunkServer.
     *   3. Start PeerDiscovery.
     *   4. Loop over missing chunks: peer first, CDN fallback.
     *   5. Assemble and complete.
     */
    private void runDownload(String version, String manifestJson) {
        MeshDownloadCallback cb = mCallback;

        // 1. Create ChunkManager
        ChunkManager cm;
        try {
            cm = new ChunkManager(getContext(), version, manifestJson);
        } catch (Exception e) {
            Slog.e(TAG, "runDownload: failed to create ChunkManager", e);
            if (cb != null) cb.onFailed("Manifest parse error: " + e.getMessage());
            return;
        }
        mChunkManager = cm;

        int total = cm.getTotalChunks();
        Slog.i(TAG, "runDownload: total=" + total + " have=" + countHave(cm));

        // Initial progress report
        if (cb != null) cb.onProgress(countHave(cm), total);

        // 2. Start ChunkServer so we can serve what we already have
        ChunkServer server = new ChunkServer(getContext(), cm);
        mChunkServer = server;
        try {
            server.start();
        } catch (IOException e) {
            // Non-fatal — we can still download even if we can't serve
            Slog.w(TAG, "runDownload: ChunkServer failed to start (will not serve peers)", e);
        }

        // 3. Start PeerDiscovery
        PeerDiscovery discovery = new PeerDiscovery(getContext(), new PeerDiscovery.PeerListener() {
            @Override
            public void onPeerFound(PeerDiscovery.PeerInfo peer) {
                Slog.i(TAG, "Peer available: " + peer);
                // Immediately schedule a fill pass when a new peer appears
                mHandler.post(() -> fillMissingChunksFromPeers(cm, discovery, cb, total));
            }
            @Override
            public void onPeerLost(String peerId) {
                Slog.i(TAG, "Peer lost: " + peerId);
            }
        });
        mPeerDiscovery = discovery;

        // Also register ourselves so other devices discover us
        discovery.registerSelf(version, cm.getChunkBitmap());
        discovery.startDiscovery(version);

        // 4. Attempt to download all missing chunks
        fillMissingChunksFromPeers(cm, discovery, cb, total);

        // 5. CDN fallback for any still-missing chunks
        if (mDownloadRunning.get()) {
            fillMissingChunksFromCdn(cm, version, cb, total);
        }

        // 6. Check completion
        if (!mDownloadRunning.get()) {
            Slog.i(TAG, "runDownload: cancelled before completion");
            return;
        }

        if (cm.isComplete()) {
            assembleAndComplete(cm, cb);
        } else {
            int missing = cm.getMissingChunkIndices().size();
            Slog.e(TAG, "runDownload: still missing " + missing + " chunks after all sources");
            if (cb != null) cb.onFailed("Could not acquire " + missing + " chunks");
        }
    }

    // -------------------------------------------------------------------------
    // Peer-based acquisition
    // -------------------------------------------------------------------------

    /**
     * Iterates over missing chunks and tries to download each one from
     * a known peer. Updates progress every {@link #PROGRESS_INTERVAL} chunks.
     */
    private void fillMissingChunksFromPeers(ChunkManager cm,
            PeerDiscovery discovery, MeshDownloadCallback cb, int total) {
        if (!mDownloadRunning.get()) return;

        List<Integer> missing = cm.getMissingChunkIndices();
        if (missing.isEmpty()) return;

        Slog.i(TAG, "fillMissingChunksFromPeers: " + missing.size() + " chunks to fetch");

        int acquired = 0;
        for (int chunkIndex : missing) {
            if (!mDownloadRunning.get()) break;

            byte[] data = tryPeersForChunk(discovery, chunkIndex);
            if (data != null) {
                boolean saved = cm.saveChunk(chunkIndex, data);
                if (saved) {
                    acquired++;
                    // Update our registration bitmap so new peers see our updated state
                    discovery.registerSelf(/* version inferred from cm */ null,
                            cm.getChunkBitmap());

                    if (acquired % PROGRESS_INTERVAL == 0 && cb != null) {
                        int have = countHave(cm);
                        cb.onProgress(have, total);
                    }
                }
            }
        }

        if (acquired > 0 && cb != null) {
            cb.onProgress(countHave(cm), total);
        }
    }

    /**
     * Tries each known peer in turn for chunk {@code chunkIndex}.
     *
     * @return The raw chunk bytes if any peer provides it, otherwise null.
     */
    private byte[] tryPeersForChunk(PeerDiscovery discovery, int chunkIndex) {
        // PeerDiscovery maintains its peer map internally; we ask ChunkClient
        // to probe each one. Since PeerDiscovery does not expose a public peer
        // list directly, we collect peer info from the last onPeerFound callbacks
        // stored in our local list. In practice CircleMeshService drives this
        // through the PeerListener, but for a clean API we use a separate
        // snapshot field maintained below.
        List<PeerDiscovery.PeerInfo> peers = getKnownPeers();
        for (PeerDiscovery.PeerInfo peer : peers) {
            if (!mDownloadRunning.get()) break;
            // Only attempt if peer's bitmap indicates it has this chunk
            byte[] bitmap = peer.chunkBitmap;
            if (bitmap != null && chunkIndex < bitmap.length && bitmap[chunkIndex] == 0) {
                continue; // Peer doesn't have it
            }
            byte[] data = ChunkClient.downloadChunk(peer, chunkIndex);
            if (data != null && data.length > 0) {
                Slog.d(TAG, "tryPeersForChunk: got chunk " + chunkIndex
                        + " from peer " + peer.address);
                return data;
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // CDN fallback
    // -------------------------------------------------------------------------

    /**
     * Downloads any remaining missing chunks directly from the CDN via HTTP
     * range requests.
     *
     * URL pattern: {@code CDN_BASE_URL}{version}/{chunkIndex:03d}.chunk
     */
    private void fillMissingChunksFromCdn(ChunkManager cm, String version,
            MeshDownloadCallback cb, int total) {
        List<Integer> missing = cm.getMissingChunkIndices();
        if (missing.isEmpty()) return;

        Slog.i(TAG, "fillMissingChunksFromCdn: " + missing.size() + " chunks via CDN");

        int acquired = 0;
        for (int chunkIndex : missing) {
            if (!mDownloadRunning.get()) break;

            byte[] data = downloadChunkFromCdn(version, chunkIndex);
            if (data != null) {
                boolean saved = cm.saveChunk(chunkIndex, data);
                if (saved) {
                    acquired++;
                    if (acquired % PROGRESS_INTERVAL == 0 && cb != null) {
                        cb.onProgress(countHave(cm), total);
                    }
                }
            }
        }

        if (acquired > 0 && cb != null) {
            cb.onProgress(countHave(cm), total);
        }
    }

    /**
     * Fetches a single chunk from the CDN.
     *
     * @param version    OTA version string.
     * @param chunkIndex Zero-based chunk index.
     * @return Raw chunk bytes, or null on failure.
     */
    private byte[] downloadChunkFromCdn(String version, int chunkIndex) {
        String url = CDN_BASE_URL + sanitizeVersion(version)
                + "/" + String.format("%03d", chunkIndex) + ".chunk";
        Slog.d(TAG, "CDN fetch: " + url);

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(CDN_CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(CDN_READ_TIMEOUT_MS);
            conn.setRequestMethod("GET");

            int code = conn.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                Slog.w(TAG, "CDN fetch: HTTP " + code + " for " + url);
                return null;
            }

            int contentLen = conn.getContentLength();
            try (InputStream in = conn.getInputStream()) {
                if (contentLen > 0) {
                    byte[] buf = new byte[contentLen];
                    int offset = 0;
                    while (offset < contentLen) {
                        int n = in.read(buf, offset, contentLen - offset);
                        if (n < 0) break;
                        offset += n;
                    }
                    return buf;
                } else {
                    // Unknown content length — read until EOF
                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    byte[] tmp = new byte[65536];
                    int n;
                    while ((n = in.read(tmp)) > 0) baos.write(tmp, 0, n);
                    return baos.toByteArray();
                }
            }
        } catch (IOException e) {
            Slog.w(TAG, "CDN fetch failed for chunk " + chunkIndex + ": " + e.getMessage());
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // -------------------------------------------------------------------------
    // Assembly and completion
    // -------------------------------------------------------------------------

    private void assembleAndComplete(ChunkManager cm, MeshDownloadCallback cb) {
        Slog.i(TAG, "assembleAndComplete: all chunks present, assembling");
        try {
            File assembled = cm.getCompletedFile();
            Slog.i(TAG, "assembleAndComplete: success, path=" + assembled.getAbsolutePath());
            if (cb != null) cb.onComplete(assembled);
        } catch (IOException e) {
            Slog.e(TAG, "assembleAndComplete: assembly failed", e);
            if (cb != null) cb.onFailed("Assembly/verification failed: " + e.getMessage());
        } finally {
            // Tear down peers and server — we're done
            PeerDiscovery pd = mPeerDiscovery;
            if (pd != null) pd.stopDiscovery();
            ChunkServer cs = mChunkServer;
            if (cs != null) cs.stop();
        }
    }

    // -------------------------------------------------------------------------
    // Peer list management
    // -------------------------------------------------------------------------

    /**
     * In-memory list of currently known peers, updated by PeerListener callbacks.
     * Guarded by {@code mKnownPeers}.
     */
    private final java.util.concurrent.CopyOnWriteArrayList<PeerDiscovery.PeerInfo>
            mKnownPeers = new java.util.concurrent.CopyOnWriteArrayList<>();

    /**
     * Returns a snapshot of currently known peers.
     */
    private List<PeerDiscovery.PeerInfo> getKnownPeers() {
        return mKnownPeers;
    }

    /**
     * Updates the known-peer list. Called from the PeerListener (on the
     * discovery thread) via the Handler.
     */
    private void onPeerFoundInternal(PeerDiscovery.PeerInfo peer) {
        // Replace existing entry by ID (IP address)
        mKnownPeers.removeIf(p -> p.id.equals(peer.id));
        mKnownPeers.add(peer);
    }

    private void onPeerLostInternal(String peerId) {
        mKnownPeers.removeIf(p -> p.id.equals(peerId));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Returns how many chunks are currently held in the given manager. */
    private static int countHave(ChunkManager cm) {
        int have = 0;
        byte[] bitmap = cm.getChunkBitmap();
        for (byte b : bitmap) if (b == 0x01) have++;
        return have;
    }

    private static String sanitizeVersion(String version) {
        if (version == null) return "unknown";
        return version.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
