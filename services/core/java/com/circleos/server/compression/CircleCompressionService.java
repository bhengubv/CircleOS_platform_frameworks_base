/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.compression;

import android.content.Context;
import android.os.HandlerThread;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.android.server.LocalServices;
import com.android.server.SystemService;

import za.co.circleos.compression.CompressionRequest;
import za.co.circleos.compression.CompressionResult;
import za.co.circleos.compression.CompressionStats;
import za.co.circleos.compression.ICircleCompression;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Circle Compression System Service.
 *
 * Provides on-device file compression integrated into the DMZ pipeline:
 *   Inbound:  scan → CDR → compress → release to app
 *   Outbound: compress → scan → send (Traffic Lobby hook, Phase 2)
 *
 * Service name: "circle.compression"
 *
 * Quality tiers:
 *   TIER_LOSSLESS          — zero quality loss
 *   TIER_VISUALLY_LOSSLESS — default; imperceptible loss, 40-70% savings
 *   TIER_AGGRESSIVE        — maximum savings for low-data / mesh use
 *
 * All compression is on-device — no cloud proxies, no data leaves the device.
 * Compression always includes metadata stripping for outbound files.
 *
 * Phase 2: ZSTD native backend, video transcoding (AV1/HEVC), audio Opus.
 * Phase 3: AI-powered quality decisions (face/text preservation via Inference Service).
 */
public class CircleCompressionService extends SystemService {

    private static final String TAG          = "CircleCompression";
    public  static final String SERVICE_NAME = "circle.compression";
    public  static final int    VERSION      = 1;

    /** Working directory for temp files during compression. */
    private static final String WORK_DIR = "/data/circle/compression/sessions/";

    private final BinderService mBinderService = new BinderService();
    private ImageCompressor     mImageCompressor;
    private DocumentCompressor  mDocumentCompressor;
    private ArchiveCompressor   mArchiveCompressor;
    private ZstdCompressor      mZstdCompressor;     // Phase 2: ZSTD archive backend
    private VideoCompressor     mVideoCompressor;    // Phase 2: HEVC video transcoding
    private AudioCompressor     mAudioCompressor;    // Phase 2: AAC audio transcoding
    private MetadataStripper    mMetadataStripper;
    private CompressionStatsTracker mStatsTracker;
    private HandlerThread       mWorkerThread;
    private android.os.Handler  mWorkerHandler;

    // sessionId → result (null while in progress)
    private final ConcurrentHashMap<String, CompressionResult> mSessions
            = new ConcurrentHashMap<>();
    // sessionId → compressed output file
    private final ConcurrentHashMap<String, File> mOutputFiles
            = new ConcurrentHashMap<>();

    /* ── Lifecycle ────────────────────────────────────────────────────── */

    public static class Lifecycle extends SystemService {
        private CircleCompressionService mService;
        public Lifecycle(Context ctx) { super(ctx); }

        @Override
        public void onStart() {
            mService = new CircleCompressionService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }

    public CircleCompressionService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mBinderService);
        // Register with LocalServices so other system services (Traffic Lobby, File DMZ)
        // can call compressDirect() and compressOutbound() without IPC.
        LocalServices.addService(CircleCompressionService.class, this);
        Log.i(TAG, "CircleCompressionService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            new File(WORK_DIR).mkdirs();
            mWorkerThread       = new HandlerThread("CircleCompression");
            mWorkerThread.start();
            mWorkerHandler      = new android.os.Handler(mWorkerThread.getLooper());
            mImageCompressor    = new ImageCompressor();
            mDocumentCompressor = new DocumentCompressor();
            mArchiveCompressor  = new ArchiveCompressor();
            mZstdCompressor     = new ZstdCompressor();   // Phase 2
            mVideoCompressor    = new VideoCompressor();  // Phase 2
            mAudioCompressor    = new AudioCompressor();  // Phase 2
            mMetadataStripper   = new MetadataStripper();
            mStatsTracker       = new CompressionStatsTracker(getContext());
            Log.i(TAG, "CircleCompressionService boot-complete init done"
                    + " (ZSTD native=" + ZstdCompressor.isNativeAvailable() + ")");
        }
    }

    /* ── Internal API (called from CircleFileDmzService) ─────────────── */

    /**
     * Compress a file directly (blocking, on caller's thread).
     * Used internally by CircleFileDmzService on its own worker thread.
     *
     * @param inputFile  Source file (temp copy from DMZ session)
     * @param mimeType   MIME type for codec selection
     * @param tier       CompressionRequest.TIER_*
     * @param direction  CompressionRequest.DIRECTION_*
     * @return CompressionResult with output in outputFile, or STATUS_SKIPPED/ERROR
     */
    public CompressionResult compressDirect(File inputFile, File outputFile,
                                            String mimeType, int tier, int direction) {
        if (mImageCompressor == null) {
            // Service not yet initialized — return skip
            CompressionResult r = new CompressionResult();
            r.status          = CompressionResult.STATUS_SKIPPED;
            r.originalBytes   = inputFile.length();
            r.compressedBytes = r.originalBytes;
            r.method          = "not-ready";
            return r;
        }

        boolean stripMeta = (direction == CompressionRequest.DIRECTION_OUTBOUND);
        CompressionResult result = dispatchCompression(inputFile, outputFile,
                mimeType, tier, stripMeta);
        result.sessionId = "direct";

        if (mStatsTracker != null && result.status == CompressionResult.STATUS_OK) {
            mStatsTracker.record(result, direction);
        }
        return result;
    }

    /**
     * Traffic Lobby outbound hook — compress a file before it is transmitted.
     *
     * <p>Called by Traffic Lobby (or any other system service) when a large
     * outbound file is detected.  Always strips metadata.  Returns the
     * compressed file as a temp file; caller is responsible for deletion after use.
     *
     * <p>This is an alias for {@link #compressDirect} with
     * {@code direction=DIRECTION_OUTBOUND} that exposes the method via
     * {@link LocalServices} without requiring IPC.
     *
     * @param inputFile  File to compress (not modified in place).
     * @param mimeType   MIME type, or null to guess from extension.
     * @param tier       {@link CompressionRequest#TIER_VISUALLY_LOSSLESS} recommended.
     * @return CompressionResult; if STATUS_OK, outputFile contains compressed bytes.
     */
    public CompressionResult compressOutbound(File inputFile, File outputFile,
                                              String mimeType, int tier) {
        return compressDirect(inputFile, outputFile, mimeType, tier,
                CompressionRequest.DIRECTION_OUTBOUND);
    }

    /* ── Binder ───────────────────────────────────────────────────────── */

    private final class BinderService extends ICircleCompression.Stub {

        @Override
        public String compress(ParcelFileDescriptor fileFd, CompressionRequest request) {
            String sessionId = UUID.randomUUID().toString();
            mSessions.put(sessionId, null);  // mark in-progress

            File inputCopy  = new File(WORK_DIR, sessionId + ".in");
            File outputFile = new File(WORK_DIR, sessionId + ".out");

            mWorkerHandler.post(() -> {
                try {
                    // Copy PFD to temp file
                    copyFdToFile(fileFd, inputCopy);

                    boolean stripMeta = request.stripMetadata
                            || request.direction == CompressionRequest.DIRECTION_OUTBOUND;

                    CompressionResult result = dispatchCompression(
                            inputCopy, outputFile,
                            request.mimeType, request.tier, stripMeta);
                    result.sessionId = sessionId;

                    if (result.status == CompressionResult.STATUS_OK) {
                        mOutputFiles.put(sessionId, outputFile);
                    }
                    mSessions.put(sessionId, result);

                    if (mStatsTracker != null && result.status == CompressionResult.STATUS_OK) {
                        mStatsTracker.record(result, request.direction);
                    }
                    Log.i(TAG, "Compressed [" + sessionId + "] "
                            + result.method + " " + result.originalBytes
                            + " → " + result.compressedBytes
                            + " (" + result.savingsPercent + "% saved)");
                } catch (Exception e) {
                    Log.e(TAG, "Compression failed for session " + sessionId, e);
                    CompressionResult err = new CompressionResult();
                    err.sessionId = sessionId;
                    err.status    = CompressionResult.STATUS_ERROR;
                    mSessions.put(sessionId, err);
                } finally {
                    inputCopy.delete();
                    try { fileFd.close(); } catch (Exception ignored) {}
                }
            });

            return sessionId;
        }

        @Override
        public CompressionResult getResult(String sessionId) {
            return mSessions.get(sessionId);
        }

        @Override
        public ParcelFileDescriptor getCompressedFile(String sessionId) {
            File f = mOutputFiles.get(sessionId);
            if (f == null || !f.exists()) return null;
            try {
                return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
            } catch (IOException e) {
                Log.e(TAG, "Cannot open compressed file for " + sessionId, e);
                return null;
            }
        }

        @Override
        public void releaseSession(String sessionId) {
            mSessions.remove(sessionId);
            File f = mOutputFiles.remove(sessionId);
            if (f != null) f.delete();
            new File(WORK_DIR, sessionId + ".in").delete();
        }

        @Override
        public CompressionStats getMonthlyStats() {
            return mStatsTracker != null ? mStatsTracker.getStats() : new CompressionStats();
        }

        @Override
        public void resetMonthlyStats() {
            if (mStatsTracker != null) mStatsTracker.reset();
        }

        @Override
        public int getServiceVersion() { return VERSION; }
    }

    /* ── Compression dispatch ─────────────────────────────────────────── */

    /**
     * Route to the appropriate compressor based on MIME type.
     * Metadata stripping runs after compression for image types (EXIF via ExifInterface).
     * For other types, stripping is done inline by the compressor.
     */
    private CompressionResult dispatchCompression(File inputFile, File outputFile,
                                                  String mimeType, int tier,
                                                  boolean stripMeta) {
        if (mimeType == null) mimeType = guessMime(inputFile.getName());
        CompressionResult result;

        if (isImage(mimeType)) {
            result = mImageCompressor.compress(inputFile, outputFile, mimeType, tier, stripMeta);
        } else if (isDocument(mimeType, inputFile.getName())) {
            result = mDocumentCompressor.compress(inputFile, outputFile, mimeType, tier);
            // Outbound: also strip remaining metadata
            if (stripMeta && result.status == CompressionResult.STATUS_OK) {
                boolean stripped = mMetadataStripper.strip(outputFile, mimeType);
                if (stripped) result.metadataStripped = true;
            }
        } else if (isArchive(mimeType, inputFile.getName())) {
            // Phase 2: use ZSTD compressor (degrades to DEFLATE-9 if native not loaded)
            result = (mZstdCompressor != null)
                    ? mZstdCompressor.compress(inputFile, outputFile, tier)
                    : mArchiveCompressor.compress(inputFile, outputFile, mimeType, tier);
        } else if (isVideo(mimeType, inputFile.getName())) {
            // Phase 2: HEVC video transcoding
            result = (mVideoCompressor != null)
                    ? mVideoCompressor.compress(inputFile, outputFile, tier)
                    : skip(inputFile, "video-phase2-not-ready");
        } else if (isAudio(mimeType, inputFile.getName())) {
            // Phase 2: AAC audio transcoding
            result = (mAudioCompressor != null)
                    ? mAudioCompressor.compress(inputFile, outputFile, tier)
                    : skip(inputFile, "audio-phase2-not-ready");
        } else {
            // Unknown type — outbound metadata strip only, no compression
            if (stripMeta) {
                try {
                    copyFile(inputFile, outputFile);
                    boolean stripped = mMetadataStripper.strip(outputFile, mimeType);
                    result = new CompressionResult();
                    result.status          = stripped ? CompressionResult.STATUS_OK
                                                      : CompressionResult.STATUS_SKIPPED;
                    result.originalBytes   = inputFile.length();
                    result.compressedBytes = outputFile.length();
                    result.method          = "meta-strip-only";
                    result.metadataStripped = stripped;
                } catch (IOException e) {
                    result = new CompressionResult();
                    result.status = CompressionResult.STATUS_ERROR;
                }
            } else {
                result = new CompressionResult();
                result.status          = CompressionResult.STATUS_SKIPPED;
                result.originalBytes   = inputFile.length();
                result.compressedBytes = inputFile.length();
                result.method          = "passthrough";
            }
        }

        return result;
    }

    /* ── Helpers ─────────────────────────────────────────────────────── */

    private boolean isImage(String m) {
        return m != null && m.startsWith("image/");
    }

    private boolean isDocument(String m, String name) {
        if ("application/pdf".equals(m)) return true;
        if (m != null && m.startsWith("application/vnd.openxmlformats")) return true;
        if (m != null && m.startsWith("application/vnd.oasis.opendocument")) return true;
        String n = name.toLowerCase();
        return n.endsWith(".docx") || n.endsWith(".xlsx") || n.endsWith(".pptx")
            || n.endsWith(".odt")  || n.endsWith(".ods")  || n.endsWith(".odp");
    }

    private boolean isArchive(String m, String name) {
        if ("application/zip".equals(m) || "application/x-zip-compressed".equals(m)) return true;
        return name.toLowerCase().endsWith(".zip");
    }

    private boolean isVideo(String m, String name) {
        if (m != null && m.startsWith("video/")) return true;
        String n = name.toLowerCase();
        return n.endsWith(".mp4") || n.endsWith(".mov") || n.endsWith(".mkv")
            || n.endsWith(".avi") || n.endsWith(".webm") || n.endsWith(".3gp");
    }

    private boolean isAudio(String m, String name) {
        if (m != null && m.startsWith("audio/")) return true;
        String n = name.toLowerCase();
        return n.endsWith(".mp3") || n.endsWith(".aac") || n.endsWith(".m4a")
            || n.endsWith(".ogg") || n.endsWith(".flac") || n.endsWith(".opus");
    }

    private CompressionResult skip(File inputFile, String method) {
        CompressionResult r = new CompressionResult();
        r.status          = CompressionResult.STATUS_SKIPPED;
        r.originalBytes   = inputFile.length();
        r.compressedBytes = r.originalBytes;
        r.method          = method;
        return r;
    }

    private String guessMime(String name) {
        String n = name.toLowerCase();
        if (n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
        if (n.endsWith(".png"))  return "image/png";
        if (n.endsWith(".webp")) return "image/webp";
        if (n.endsWith(".gif"))  return "image/gif";
        if (n.endsWith(".pdf"))  return "application/pdf";
        if (n.endsWith(".zip"))  return "application/zip";
        if (n.endsWith(".docx")) return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        // Phase 2: video and audio
        if (n.endsWith(".mp4") || n.endsWith(".mov")) return "video/mp4";
        if (n.endsWith(".mkv"))  return "video/x-matroska";
        if (n.endsWith(".webm")) return "video/webm";
        if (n.endsWith(".mp3"))  return "audio/mpeg";
        if (n.endsWith(".aac") || n.endsWith(".m4a")) return "audio/mp4";
        if (n.endsWith(".ogg"))  return "audio/ogg";
        if (n.endsWith(".flac")) return "audio/flac";
        if (n.endsWith(".opus")) return "audio/opus";
        return "application/octet-stream";
    }

    private void copyFdToFile(ParcelFileDescriptor pfd, File dest) throws IOException {
        try (FileInputStream fis = new FileInputStream(pfd.getFileDescriptor());
             FileOutputStream fos = new FileOutputStream(dest)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) != -1) fos.write(buf, 0, n);
        }
    }

    private void copyFile(File src, File dst) throws IOException {
        try (FileInputStream fis  = new FileInputStream(src);
             FileOutputStream fos = new FileOutputStream(dst)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) != -1) fos.write(buf, 0, n);
        }
    }
}
