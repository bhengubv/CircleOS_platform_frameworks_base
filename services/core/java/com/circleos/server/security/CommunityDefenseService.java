/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.content.Context;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.security.AttackCampaign;
import za.co.circleos.security.DmzAnalysisResult;
import za.co.circleos.security.QuarantineRecord;
import za.co.circleos.security.ThreatIndicator;

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
    private final CampaignCorrelator mCampaignCorrelator = new CampaignCorrelator();
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
        long now = System.currentTimeMillis();
        int conf = confidenceForVerdict(result.verdict);

        List<ThreatIndicator> indicators = new ArrayList<>();

        if (result.sha256 != null && !result.sha256.isEmpty()) {
            if (mEnabled) enqueue(new AnonymizedIoc(
                    AnonymizedIoc.Type.HASH, result.sha256, result.verdict, conf));
            indicators.add(makeTi(ThreatIndicator.TYPE_FILE_HASH,
                    result.sha256, conf, "dmz", now));
        }
        for (String addr : result.c2Addresses) {
            boolean isIp = addr.matches("\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?");
            if (mEnabled) enqueue(new AnonymizedIoc(
                    isIp ? AnonymizedIoc.Type.IP : AnonymizedIoc.Type.DOMAIN,
                    addr, result.verdict, conf));
            indicators.add(makeTi(
                    isIp ? ThreatIndicator.TYPE_IP_ADDRESS : ThreatIndicator.TYPE_DOMAIN,
                    addr, conf, "dmz", now));
        }
        if (!indicators.isEmpty()) mCampaignCorrelator.correlate(indicators);
    }

    /** Submit IOCs from a quarantine record. */
    public void submitFromQuarantine(QuarantineRecord record) {
        long now = System.currentTimeMillis();
        List<ThreatIndicator> indicators = new ArrayList<>();

        if (record.sha256 != null) {
            if (mEnabled) enqueue(new AnonymizedIoc(
                    AnonymizedIoc.Type.HASH, record.sha256, DmzAnalysisResult.VERDICT_THREAT, 3));
            indicators.add(makeTi(ThreatIndicator.TYPE_FILE_HASH, record.sha256, 3, "quarantine", now));
        }
        for (String ioc : record.iocExtracted) {
            boolean isIp = ioc.matches("\\d{1,3}(\\.\\d{1,3}){3}.*");
            if (!ioc.startsWith("BEHAVIORAL:") && !ioc.startsWith("CDR:")) {
                if (mEnabled) enqueue(new AnonymizedIoc(
                        isIp ? AnonymizedIoc.Type.IP : AnonymizedIoc.Type.DOMAIN,
                        ioc, DmzAnalysisResult.VERDICT_THREAT, 2));
                indicators.add(makeTi(
                        isIp ? ThreatIndicator.TYPE_IP_ADDRESS : ThreatIndicator.TYPE_DOMAIN,
                        ioc, 2, "quarantine", now));
            }
        }
        if (!indicators.isEmpty()) mCampaignCorrelator.correlate(indicators);
    }

    /**
     * Ingest ThreatIndicators shared by a mesh peer.
     * Runs correlation regardless of community-defense opt-in (local correlation only).
     */
    public void receivePeerThreatIndicators(List<ThreatIndicator> indicators) {
        if (indicators == null || indicators.isEmpty()) return;
        List<String> touched = mCampaignCorrelator.correlate(indicators);
        Log.i(TAG, "Peer IOCs received: " + indicators.size()
                + " → " + touched.size() + " campaign(s) affected");
    }

    /** Returns all correlated attack campaigns seen on this device. */
    public List<AttackCampaign> getActiveCampaigns() {
        return mCampaignCorrelator.getAllCampaigns();
    }

    /** Returns a specific campaign by ID, or null. */
    public AttackCampaign getCampaign(String campaignId) {
        return mCampaignCorrelator.getCampaign(campaignId);
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

    private static ThreatIndicator makeTi(int type, String value, int confidence,
                                          String source, long now) {
        ThreatIndicator ti = new ThreatIndicator();
        ti.type       = type;
        ti.value      = value;
        ti.confidence = confidence;
        ti.source     = source;
        ti.firstSeen  = now;
        ti.lastSeen   = now;
        return ti;
    }
}
