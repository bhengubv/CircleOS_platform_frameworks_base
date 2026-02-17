/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.content.Context;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.security.DmzAnalysisResult;
import za.co.circleos.security.ICircleFileDmz;
import za.co.circleos.security.ThreatIndicator;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Circle File DMZ System Service.
 *
 * Provides on-device file analysis: static scan → threat feed match →
 * Content Disarm and Reconstruction (CDR).
 *
 * Service name: "circle.file_dmz"
 */
public class CircleFileDmzService extends SystemService {

    private static final String TAG          = "CircleFileDmz";
    public  static final String SERVICE_NAME = "circle.file_dmz";
    public  static final int    VERSION      = 1;

    private final BinderService mBinderService = new BinderService();
    private ThreatFeedDatabase    mFeedDb;
    private CdrProcessor          mCdrProcessor;
    private BehavioralSandbox     mBehavioralSandbox;
    private QuarantineManager     mQuarantineManager;
    private CommunityDefenseService mCommunityDefense;
    private ResearcherApiService  mResearcherApi;
    private com.circleos.server.compression.CircleCompressionService mCompressionService;
    private HandlerThread         mWorkerThread;
    private android.os.Handler    mWorkerHandler;

    // Active analysis sessions: sessionId → result (null while in progress)
    private final ConcurrentHashMap<String, DmzAnalysisResult> mSessions
            = new ConcurrentHashMap<>();

    /* ── Lifecycle ────────────────────────────────────────────────────── */

    public static class Lifecycle extends SystemService {
        private CircleFileDmzService mService;

        public Lifecycle(Context ctx) { super(ctx); }

        @Override
        public void onStart() {
            mService = new CircleFileDmzService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }

    public CircleFileDmzService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mBinderService);
        Log.i(TAG, "CircleFileDmzService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            mWorkerThread  = new HandlerThread("CircleFileDmz");
            mWorkerThread.start();
            mWorkerHandler = new android.os.Handler(mWorkerThread.getLooper());

            mFeedDb             = new ThreatFeedDatabase();
            mCdrProcessor       = new CdrProcessor();
            mBehavioralSandbox  = new BehavioralSandbox();
            mQuarantineManager  = new QuarantineManager(getContext());
            mCommunityDefense   = new CommunityDefenseService(getContext());
            mResearcherApi      = new ResearcherApiService(getContext());
            mQuarantineManager.setResearcherApi(mResearcherApi);
            mCompressionService = new com.circleos.server.compression.CircleCompressionService(getContext());

            // Kick off initial feed update
            mWorkerHandler.post(() -> {
                ThreatFeedUpdater updater = new ThreatFeedUpdater(mFeedDb);
                updater.updateIfStale();
            });
            Log.i(TAG, "CircleFileDmzService boot-complete init done");
        }
    }

    /* ── Binder implementation ─────────────────────────────────────────── */

    private final class BinderService extends ICircleFileDmz.Stub {

        @Override
        public String submitFile(ParcelFileDescriptor fileFd,
                                 String fileName, String mimeType, String sourceApp) {
            String sessionId = UUID.randomUUID().toString();
            // Queue async analysis
            mWorkerHandler.post(() -> analyzeFile(sessionId, fileFd, fileName, mimeType, sourceApp));
            return sessionId;
        }

        @Override
        public DmzAnalysisResult getResult(String sessionId) {
            // Poll — caller should retry until non-null
            return mSessions.get(sessionId);
        }

        @Override
        public ParcelFileDescriptor getSanitizedFile(String sessionId) {
            DmzAnalysisResult r = mSessions.get(sessionId);
            if (r == null || !r.hasSanitizedVersion) return null;
            return mCdrProcessor.getSanitizedFd(sessionId);
        }

        @Override
        public void releaseSession(String sessionId) {
            mSessions.remove(sessionId);
            mCdrProcessor.releaseSession(sessionId);
        }

        @Override
        public List<DmzAnalysisResult> listQuarantined() {
            return mFeedDb.listQuarantined();
        }

        @Override
        public void deleteQuarantined(String sessionId) {
            mFeedDb.deleteQuarantined(sessionId);
        }

        @Override
        public boolean isHashKnownMalicious(String sha256Hex) {
            return mFeedDb != null && mFeedDb.isHashBlocked(sha256Hex);
        }

        @Override
        public boolean isDomainBlacklisted(String domain) {
            return mFeedDb != null && mFeedDb.isDomainBlocked(domain);
        }

        @Override
        public boolean isIpBlacklisted(String ip) {
            return mFeedDb != null && mFeedDb.isIpBlocked(ip);
        }

        @Override
        public void triggerFeedUpdate() {
            if (mWorkerHandler != null) {
                mWorkerHandler.post(() -> new ThreatFeedUpdater(mFeedDb).forceUpdate());
            }
        }

        @Override
        public int getServiceVersion() {
            return VERSION;
        }
    }

    /* ── Analysis pipeline ─────────────────────────────────────────────── */

    private void analyzeFile(String sessionId, ParcelFileDescriptor fileFd,
                             String fileName, String mimeType, String sourceApp) {
        long start = System.currentTimeMillis();
        DmzAnalysisResult result = new DmzAnalysisResult();
        result.sessionId    = sessionId;
        result.fileName     = fileName;
        result.mimeType     = mimeType;
        result.sourceApp    = sourceApp;
        result.stageReached = DmzAnalysisResult.STAGE_INTAKE;

        try {
            // Stage 1: SHA-256 + known-hash check
            result.stageReached = DmzAnalysisResult.STAGE_STATIC;
            String sha256 = hashFile(fileFd);
            result.sha256 = sha256;

            if (mFeedDb != null && mFeedDb.isHashBlocked(sha256)) {
                result.verdict           = DmzAnalysisResult.VERDICT_THREAT;
                result.knownMaliciousHash = true;
                result.findings.add("File hash matches known malware: " + sha256);
                mSessions.put(sessionId, result);
                return;
            }

            // Stage 2: Behavioral analysis (static pattern analysis)
            result.stageReached = DmzAnalysisResult.STAGE_SANDBOXED;
            BehavioralSandbox.SandboxResult sandboxResult =
                    mBehavioralSandbox.analyze(fileFd, mimeType, result);

            // Escalate to THREAT if sandbox found embedded executables or macros
            if (sandboxResult.suspiciousActivity) {
                // Re-check against threat feeds with extracted IOCs
                for (String url : sandboxResult.extractedUrls) {
                    String host = url.replaceFirst("https?://", "").split("/")[0];
                    if (mFeedDb != null && mFeedDb.isDomainBlocked(host)) {
                        result.verdict = DmzAnalysisResult.VERDICT_THREAT;
                        result.findings.add("Extracted URL matches C2 feed: " + host);
                        mQuarantineManager.quarantine(result, null);
                        mCommunityDefense.submitFromDmzResult(result);
                        mSessions.put(sessionId, result);
                        return;
                    }
                }
            }

            // Stage 3: CDR (Phase 2 — Office, HTML, ZIP, Video/Audio added)
            result.stageReached = DmzAnalysisResult.STAGE_CDR;
            boolean sanitized = mCdrProcessor.process(sessionId, fileFd, mimeType, result);
            if (sanitized) {
                result.hasSanitizedVersion = true;
                result.verdict = sandboxResult.suspiciousActivity
                        ? DmzAnalysisResult.VERDICT_SUSPICIOUS
                        : DmzAnalysisResult.VERDICT_SANITIZED;
            } else {
                result.verdict = sandboxResult.suspiciousActivity
                        ? DmzAnalysisResult.VERDICT_SUSPICIOUS
                        : DmzAnalysisResult.VERDICT_CLEAN;
            }

            // Stage 4: Compression — runs on all clean/sanitized inbound files
            if (mCompressionService != null
                    && (result.verdict == DmzAnalysisResult.VERDICT_CLEAN
                     || result.verdict == DmzAnalysisResult.VERDICT_SANITIZED
                     || result.verdict == DmzAnalysisResult.VERDICT_SUSPICIOUS)) {
                java.io.File cdrOutput = mCdrProcessor.getSanitizedFile(sessionId);
                if (cdrOutput != null && cdrOutput.exists()) {
                    java.io.File compOut = new java.io.File(
                            cdrOutput.getParent(), sessionId + ".compressed");
                    za.co.circleos.compression.CompressionResult cr =
                            mCompressionService.compressDirect(
                                    cdrOutput, compOut, mimeType,
                                    za.co.circleos.compression.CompressionRequest.TIER_VISUALLY_LOSSLESS,
                                    za.co.circleos.compression.CompressionRequest.DIRECTION_INBOUND);
                    if (cr.status == za.co.circleos.compression.CompressionResult.STATUS_OK) {
                        result.findings.add("Compressed: " + cr.originalBytes
                                + " → " + cr.compressedBytes
                                + " bytes (" + cr.savingsPercent + "% saved, method=" + cr.method + ")");
                        // Replace CDR output with compressed version
                        compOut.renameTo(cdrOutput);
                        result.hasSanitizedVersion = true;
                    }
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Analysis failed for " + sessionId, e);
            result.verdict   = DmzAnalysisResult.VERDICT_ERROR;
            result.errorCode = DmzAnalysisResult.ERROR_INTERNAL;
        } finally {
            result.analysisDurationMs = System.currentTimeMillis() - start;
            mSessions.put(sessionId, result);
            // Feed researcher API with any non-clean result
            if (mResearcherApi != null
                    && result.verdict != DmzAnalysisResult.VERDICT_CLEAN
                    && result.verdict != DmzAnalysisResult.VERDICT_ERROR) {
                mResearcherApi.processDmzResult(result);
            }
            try { fileFd.close(); } catch (Exception ignored) {}
        }
    }

    private String hashFile(ParcelFileDescriptor fileFd) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(fileFd.getFileDescriptor())) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) != -1) md.update(buf, 0, n);
        }
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder(64);
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
