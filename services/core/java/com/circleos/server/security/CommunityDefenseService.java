/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.content.Context;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.security.DmzAnalysisResult;
import za.co.circleos.security.QuarantineRecord;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Community Defense Service.
 *
 * Privacy-preserving, opt-in IOC sharing with the Data Acuity network.
 *
 * What is shared (hash, domain, IP verdicts ONLY):
 *   sha256_of_file → verdict
 *   domain → verdict, confidence
 *   ip → verdict, confidence
 *
 * What is NEVER shared:
 *   - File contents or any portion of file contents
 *   - User identity, device ID, phone number, IMEI
 *   - File name, path, or source app
 *   - Timestamp (batched + jittered ±30 min to prevent correlation)
 *   - Location
 *
 * Opt-in: stored in Settings.Secure, key "circle_community_defense_enabled".
 * Default: false (opt-in required).
 *
 * Batching: IOCs queued in memory, submitted every 6 hours in a randomized batch.
 * If the queue exceeds 1000 entries, oldest are dropped (defense against timing attacks).
 */
public class CommunityDefenseService extends SystemService {

    private static final String TAG          = "CircleCommunityDefense";
    public  static final String SERVICE_NAME = "circle.community_defense";

    private static final String PREF_KEY_ENABLED = "circle_community_defense_enabled";
    private static final int    MAX_QUEUE_SIZE   = 1000;
    private static final long   SUBMIT_INTERVAL_MS = 6 * 60 * 60 * 1000L; // 6 hours

    private final LinkedBlockingQueue<AnonymizedIoc> mQueue = new LinkedBlockingQueue<>();
    private DataAcuityClient mDataAcuityClient;
    private boolean mEnabled = false;

    /* ── IOC DTO ──────────────────────────────────────────────────────── */

    static final class AnonymizedIoc {
        enum Type { HASH, DOMAIN, IP }
        final Type   type;
        final String value;
        final int    verdict;    // DmzAnalysisResult.VERDICT_*
        final int    confidence; // 1-3

        AnonymizedIoc(Type type, String value, int verdict, int confidence) {
            this.type       = type;
            this.value      = value;
            this.verdict    = verdict;
            this.confidence = confidence;
        }
    }

    /* ── Lifecycle ────────────────────────────────────────────────────── */

    public static class Lifecycle extends SystemService {
        private CommunityDefenseService mService;

        public Lifecycle(Context ctx) { super(ctx); }

        @Override
        public void onStart() {
            mService = new CommunityDefenseService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }

    public CommunityDefenseService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        Log.i(TAG, "CommunityDefenseService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            mDataAcuityClient = new DataAcuityClient();
            mEnabled = isOptedIn();
            if (mEnabled) schedulePeriodicSubmission();
            Log.i(TAG, "Community Defense " + (mEnabled ? "enabled" : "disabled (opt-in required)"));
        }
    }

    /* ── Public API ─────────────────────────────────────────────────────── */

    /** Submit IOCs from a DMZ analysis result. No-op if user not opted in. */
    public void submitFromDmzResult(DmzAnalysisResult result) {
        if (!mEnabled) return;

        // Hash IOC
        if (result.sha256 != null && !result.sha256.isEmpty()) {
            enqueue(new AnonymizedIoc(AnonymizedIoc.Type.HASH, result.sha256,
                    result.verdict, confidenceForVerdict(result.verdict)));
        }
        // C2 address IOCs
        for (String addr : result.c2Addresses) {
            boolean isIp = addr.matches("\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?");
            enqueue(new AnonymizedIoc(
                    isIp ? AnonymizedIoc.Type.IP : AnonymizedIoc.Type.DOMAIN,
                    addr, result.verdict, confidenceForVerdict(result.verdict)));
        }
    }

    /** Submit IOCs from a quarantine record. */
    public void submitFromQuarantine(QuarantineRecord record) {
        if (!mEnabled) return;
        if (record.sha256 != null) {
            enqueue(new AnonymizedIoc(AnonymizedIoc.Type.HASH, record.sha256,
                    DmzAnalysisResult.VERDICT_THREAT, 3));
        }
        for (String ioc : record.iocExtracted) {
            boolean isIp = ioc.matches("\\d{1,3}(\\.\\d{1,3}){3}.*");
            if (!ioc.startsWith("BEHAVIORAL:") && !ioc.startsWith("CDR:")) {
                enqueue(new AnonymizedIoc(
                        isIp ? AnonymizedIoc.Type.IP : AnonymizedIoc.Type.DOMAIN,
                        ioc, DmzAnalysisResult.VERDICT_THREAT, 2));
            }
        }
    }

    /** Called by user to toggle opt-in. */
    public void setOptIn(boolean enabled) {
        mEnabled = enabled;
        android.provider.Settings.Secure.putInt(
                getContext().getContentResolver(), PREF_KEY_ENABLED, enabled ? 1 : 0);
        if (enabled) schedulePeriodicSubmission();
        Log.i(TAG, "Community Defense opt-in set to: " + enabled);
    }

    /* ── Internals ─────────────────────────────────────────────────────── */

    private void enqueue(AnonymizedIoc ioc) {
        if (mQueue.size() >= MAX_QUEUE_SIZE) mQueue.poll(); // drop oldest
        mQueue.offer(ioc);
    }

    private void submitBatch() {
        if (!mEnabled || mQueue.isEmpty()) return;
        List<AnonymizedIoc> batch = new ArrayList<>();
        mQueue.drainTo(batch, 500);
        if (batch.isEmpty()) return;

        // Jitter submission time ±30 min
        long jitterMs = (long)(Math.random() * 60 * 60 * 1000L) - 30 * 60 * 1000L;
        try { Thread.sleep(Math.max(0, jitterMs)); } catch (InterruptedException ignored) {}

        mDataAcuityClient.submitIocBatch(batch);
        Log.i(TAG, "Submitted " + batch.size() + " IOCs to Data Acuity");
    }

    private void schedulePeriodicSubmission() {
        Thread t = new Thread(() -> {
            while (mEnabled) {
                try { Thread.sleep(SUBMIT_INTERVAL_MS); } catch (InterruptedException ignored) {}
                submitBatch();
            }
        }, "CommunityDefense-Submitter");
        t.setDaemon(true);
        t.start();
    }

    private boolean isOptedIn() {
        return android.provider.Settings.Secure.getInt(
                getContext().getContentResolver(), PREF_KEY_ENABLED, 0) == 1;
    }

    private int confidenceForVerdict(int verdict) {
        switch (verdict) {
            case DmzAnalysisResult.VERDICT_THREAT:    return 3;
            case DmzAnalysisResult.VERDICT_SUSPICIOUS: return 2;
            default: return 1;
        }
    }
}
