/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.content.Context;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.security.AttackCampaign;
import za.co.circleos.security.IDataAcuityResearcherApi;
import za.co.circleos.security.IocBundle;
import za.co.circleos.security.ThreatIndicator;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Implements {@link IDataAcuityResearcherApi} — exposes correlated threat
 * intelligence to authorized researcher apps.
 *
 * Backed by {@link CommunityDefenseService#getActiveCampaigns()} and
 * {@link CampaignCorrelator} data.  All IOC bundles are serialized as
 * minimal STIX 2.1 JSON.
 *
 * Requires permission: {@code com.circleos.permission.RESEARCHER_API}
 */
public class DataAcuityResearcherApiService extends SystemService {

    private static final String TAG          = "DataAcuityResearcher";
    public  static final String SERVICE_NAME = "circle.researcher_api";

    private CommunityDefenseService mDefense;

    /* ── Lifecycle ───────────────────────────────────────────────────────── */

    public static class Lifecycle extends SystemService {
        private DataAcuityResearcherApiService mService;
        public Lifecycle(Context ctx) { super(ctx); }

        @Override
        public void onStart() {
            mService = new DataAcuityResearcherApiService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) { mService.onBootPhase(phase); }
    }

    public DataAcuityResearcherApiService(Context context) { super(context); }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mBinder);
        Log.i(TAG, "DataAcuityResearcherApiService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            // Retrieve sibling service reference
            mDefense = (CommunityDefenseService) getBinderService(
                    CommunityDefenseService.SERVICE_NAME);
        }
    }

    /* ── Binder ──────────────────────────────────────────────────────────── */

    private final IDataAcuityResearcherApi.Stub mBinder = new IDataAcuityResearcherApi.Stub() {

        @Override
        public List<AttackCampaign> listCampaigns(int maxResults) {
            List<AttackCampaign> all = campaigns();
            if (maxResults <= 0 || maxResults >= all.size()) return all;
            return all.subList(0, maxResults);
        }

        @Override
        public AttackCampaign getCampaign(String campaignId) {
            return mDefense != null ? mDefense.getCampaign(campaignId) : null;
        }

        @Override
        public IocBundle getIocBundle(String campaignId) {
            AttackCampaign c = mDefense != null ? mDefense.getCampaign(campaignId) : null;
            if (c == null) return null;
            List<AttackCampaign> single = new ArrayList<>();
            single.add(c);
            return buildBundle(single, 0);
        }

        @Override
        public IocBundle getAllIocs(long sinceEpochMs, int maxResults) {
            List<AttackCampaign> all = campaigns();
            List<AttackCampaign> filtered = new ArrayList<>();
            for (AttackCampaign c : all) {
                if (c.lastSeenMs >= sinceEpochMs) filtered.add(c);
            }
            if (maxResults > 0 && filtered.size() > maxResults) {
                filtered = filtered.subList(0, maxResults);
            }
            return buildBundle(filtered, sinceEpochMs);
        }

        @Override
        public IocBundle pollNewIocs(long sinceEpochMs) {
            return getAllIocs(sinceEpochMs, 0);
        }

        @Override
        public List<String> getRelatedInfrastructure(String ipOrDomain) {
            List<String> related = new ArrayList<>();
            for (AttackCampaign c : campaigns()) {
                if (c.iocs.contains(ipOrDomain)) {
                    for (String ioc : c.iocs) {
                        if (!ioc.equals(ipOrDomain) && !related.contains(ioc)) {
                            related.add(ioc);
                        }
                    }
                }
            }
            return related;
        }

        @Override
        public List<String> predictRelatedInfrastructure(String campaignId) {
            AttackCampaign c = mDefense != null ? mDefense.getCampaign(campaignId) : null;
            if (c == null) return new ArrayList<>();
            // Prediction: return IOCs from the same /24 subnet as any campaign IP
            List<String> predicted = new ArrayList<>();
            for (String ioc : c.iocs) {
                if (ioc.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                    String subnet = subnet24(ioc);
                    if (subnet != null) predicted.add(subnet + ".0/24");
                }
            }
            return predicted;
        }

        @Override
        public int getTotalCampaigns() {
            return campaigns().size();
        }

        @Override
        public int getTotalIocs() {
            int total = 0;
            for (AttackCampaign c : campaigns()) total += c.iocs.size();
            return total;
        }

        @Override
        public int getServiceVersion() { return 1; }
    };

    /* ── Helpers ─────────────────────────────────────────────────────────── */

    private List<AttackCampaign> campaigns() {
        return mDefense != null ? mDefense.getActiveCampaigns() : new ArrayList<>();
    }

    /**
     * Build a minimal STIX 2.1 bundle JSON from the given campaigns.
     * Produces: bundle → indicators (one per IOC) + campaign objects.
     */
    private IocBundle buildBundle(List<AttackCampaign> campaigns, long sinceEpochMs) {
        long now = System.currentTimeMillis();
        IocBundle bundle = new IocBundle();
        bundle.bundleId      = UUID.randomUUID().toString();
        bundle.generatedAtMs = now;
        bundle.campaignCount = campaigns.size();

        long oldest = Long.MAX_VALUE, newest = 0;
        int iocCount = 0;

        StringBuilder json = new StringBuilder();
        json.append("{\"type\":\"bundle\",\"id\":\"bundle--")
            .append(UUID.randomUUID()).append("\",\"objects\":[");

        boolean first = true;
        for (AttackCampaign c : campaigns) {
            // Campaign STIX object
            if (!first) json.append(",");
            json.append("{\"type\":\"campaign\",\"id\":\"").append(stixSafe(c.stixId))
                .append("\",\"name\":\"").append(stixSafe(c.name))
                .append("\",\"description\":\"").append(stixSafe(c.description))
                .append("\",\"first_seen\":\"").append(epochToStix(c.firstSeenMs))
                .append("\",\"last_seen\":\"").append(epochToStix(c.lastSeenMs))
                .append("\",\"confidence\":").append(c.confidence * 33) // map 1-3 → 33/66/99
                .append("}");
            first = false;

            if (c.firstSeenMs > 0 && c.firstSeenMs < oldest) oldest = c.firstSeenMs;
            if (c.lastSeenMs  > newest) newest = c.lastSeenMs;

            // Indicator objects for each IOC
            for (String ioc : c.iocs) {
                iocCount++;
                String patternType = stixPatternType(ioc);
                json.append(",{\"type\":\"indicator\",\"id\":\"indicator--")
                    .append(UUID.nameUUIDFromBytes(ioc.getBytes(StandardCharsets.UTF_8)))
                    .append("\",\"pattern_type\":\"stix\",\"pattern\":\"[")
                    .append(patternType).append(" = '").append(stixSafe(ioc)).append("']")
                    .append("\",\"valid_from\":\"").append(epochToStix(c.firstSeenMs))
                    .append("\",\"relationship\":\"").append(stixSafe(c.stixId))
                    .append("\"}");
            }
        }
        json.append("]}");

        bundle.stixJson   = json.toString();
        bundle.iocCount   = iocCount;
        bundle.oldestIocMs = oldest == Long.MAX_VALUE ? 0 : oldest;
        bundle.newestIocMs = newest;
        return bundle;
    }

    private static String stixSafe(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String epochToStix(long epochMs) {
        // ISO-8601 UTC — simplified without java.time (API 26+)
        java.util.Date d = new java.util.Date(epochMs);
        java.util.Calendar cal = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"));
        cal.setTime(d);
        return String.format("%04d-%02d-%02dT%02d:%02d:%02d.000Z",
                cal.get(java.util.Calendar.YEAR),
                cal.get(java.util.Calendar.MONTH) + 1,
                cal.get(java.util.Calendar.DAY_OF_MONTH),
                cal.get(java.util.Calendar.HOUR_OF_DAY),
                cal.get(java.util.Calendar.MINUTE),
                cal.get(java.util.Calendar.SECOND));
    }

    private static String stixPatternType(String ioc) {
        if (ioc.matches("\\d{1,3}(\\.\\d{1,3}){3}.*")) return "ipv4-addr:value";
        if (ioc.matches("[0-9a-fA-F]{32,}"))             return "file:hashes.'SHA-256'";
        return "domain-name:value";
    }

    private static String subnet24(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length < 3) return null;
        return parts[0] + "." + parts[1] + "." + parts[2];
    }
}
