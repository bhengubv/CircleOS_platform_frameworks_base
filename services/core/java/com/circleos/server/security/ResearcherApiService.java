/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.content.Context;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.security.AttackCampaign;
import za.co.circleos.security.DmzAnalysisResult;
import za.co.circleos.security.IDataAcuityResearcherApi;
import za.co.circleos.security.IocBundle;
import za.co.circleos.security.QuarantineRecord;
import za.co.circleos.security.ThreatIndicator;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Data Acuity Researcher API Service — Phase 3.
 *
 * Aggregates output from IocExtractor, CampaignCorrelator, and InfrastructureMapper
 * to provide a complete threat intelligence API for authorized researchers.
 *
 * Service name: "circle.researcher_api"
 *
 * Authorization: requires RESEARCHER_API permission (signature|privileged).
 * In production: subscription tier checked via Data Acuity API token.
 *
 * STIX 2.1 output: IocBundle.stixJson contains a complete STIX 2.1 Bundle JSON.
 *
 * Webhook / WebSocket (Phase 4): real-time IOC push to subscribed researchers.
 */
public class ResearcherApiService extends SystemService {

    private static final String TAG          = "CircleResearcherApi";
    public  static final String SERVICE_NAME = "circle.researcher_api";
    public  static final int    VERSION      = 1;

    private final BinderService     mBinderService    = new BinderService();
    private IocExtractor            mIocExtractor;
    private CampaignCorrelator      mCorrelator;
    private InfrastructureMapper    mMapper;
    private HandlerThread           mWorkerThread;
    private android.os.Handler      mWorkerHandler;

    // In-memory IOC store (Phase 3: replace with SQLite in Phase 4)
    private final CopyOnWriteArrayList<ThreatIndicator> mAllIocs
            = new CopyOnWriteArrayList<>();

    /* ── Lifecycle ────────────────────────────────────────────────────── */

    public static class Lifecycle extends SystemService {
        private ResearcherApiService mService;

        public Lifecycle(Context ctx) { super(ctx); }

        @Override
        public void onStart() {
            mService = new ResearcherApiService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }

    public ResearcherApiService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mBinderService);
        Log.i(TAG, "ResearcherApiService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            mWorkerThread  = new HandlerThread("ResearcherApi");
            mWorkerThread.start();
            mWorkerHandler = new android.os.Handler(mWorkerThread.getLooper());
            mIocExtractor  = new IocExtractor();
            mCorrelator    = new CampaignCorrelator();
            mMapper        = new InfrastructureMapper();
            Log.i(TAG, "ResearcherApiService boot-complete init done");
        }
    }

    /* ── Public API (called from CircleFileDmzService + QuarantineManager) ── */

    /** Called when a DMZ analysis completes — extract and correlate IOCs. */
    public void processDmzResult(DmzAnalysisResult result) {
        if (mWorkerHandler == null) return;
        mWorkerHandler.post(() -> {
            List<ThreatIndicator> iocs = mIocExtractor.extractFromDmzResult(result);
            mAllIocs.addAll(iocs);
            List<String> campaigns = mCorrelator.correlate(iocs);
            mMapper.ingestCampaigns(mCorrelator.getAllCampaigns());
            Log.i(TAG, "Processed DMZ result → " + iocs.size() + " IOCs, "
                    + campaigns.size() + " campaigns");
        });
    }

    /** Called when a file is quarantined. */
    public void processQuarantineRecord(QuarantineRecord record) {
        if (mWorkerHandler == null) return;
        mWorkerHandler.post(() -> {
            List<ThreatIndicator> iocs = mIocExtractor.extractFromQuarantine(record);
            mAllIocs.addAll(iocs);
            mCorrelator.correlate(iocs);
            mMapper.ingestCampaigns(mCorrelator.getAllCampaigns());
        });
    }

    /* ── Binder ───────────────────────────────────────────────────────── */

    private final class BinderService extends IDataAcuityResearcherApi.Stub {

        @Override
        public List<AttackCampaign> listCampaigns(int maxResults) {
            List<AttackCampaign> all = mCorrelator.getAllCampaigns();
            if (maxResults > 0 && all.size() > maxResults) {
                return all.subList(0, maxResults);
            }
            return all;
        }

        @Override
        public AttackCampaign getCampaign(String campaignId) {
            return mCorrelator.getCampaign(campaignId);
        }

        @Override
        public IocBundle getIocBundle(String campaignId) {
            AttackCampaign c = mCorrelator.getCampaign(campaignId);
            if (c == null) return null;
            List<ThreatIndicator> campaignIocs = new ArrayList<>();
            for (ThreatIndicator ti : mAllIocs) {
                if (c.iocs.contains(ti.value)) campaignIocs.add(ti);
            }
            return buildStixBundle(campaignIocs, 1);
        }

        @Override
        public IocBundle getAllIocs(long sinceEpochMs, int maxResults) {
            List<ThreatIndicator> filtered = new ArrayList<>();
            for (ThreatIndicator ti : mAllIocs) {
                if (ti.firstSeen >= sinceEpochMs) filtered.add(ti);
                if (maxResults > 0 && filtered.size() >= maxResults) break;
            }
            return buildStixBundle(filtered, mCorrelator.getAllCampaigns().size());
        }

        @Override
        public IocBundle pollNewIocs(long sinceEpochMs) {
            return getAllIocs(sinceEpochMs, 0);
        }

        @Override
        public List<String> getRelatedInfrastructure(String ipOrDomain) {
            return mMapper.getRelated(ipOrDomain);
        }

        @Override
        public List<String> predictRelatedInfrastructure(String campaignId) {
            return mMapper.predictRelated(campaignId);
        }

        @Override
        public int getTotalCampaigns() {
            return mCorrelator.getAllCampaigns().size();
        }

        @Override
        public int getTotalIocs() {
            return mAllIocs.size();
        }

        @Override
        public int getServiceVersion() { return VERSION; }
    }

    /* ── STIX 2.1 bundle builder ──────────────────────────────────────── */

    private IocBundle buildStixBundle(List<ThreatIndicator> iocs, int campaignCount) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"type\":\"bundle\",\"id\":\"bundle--")
          .append(UUID.randomUUID())
          .append("\",\"spec_version\":\"2.1\",\"objects\":[");

        for (int i = 0; i < iocs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(mIocExtractor.toStixIndicator(iocs.get(i)));
        }
        sb.append("]}");

        IocBundle bundle = new IocBundle();
        bundle.bundleId      = UUID.randomUUID().toString();
        bundle.stixJson      = sb.toString();
        bundle.generatedAtMs = System.currentTimeMillis();
        bundle.iocCount      = iocs.size();
        bundle.campaignCount = campaignCount;
        if (!iocs.isEmpty()) {
            bundle.oldestIocMs = iocs.stream().mapToLong(t -> t.firstSeen).min().orElse(0);
            bundle.newestIocMs = iocs.stream().mapToLong(t -> t.lastSeen).max().orElse(0);
        }
        return bundle;
    }
}
