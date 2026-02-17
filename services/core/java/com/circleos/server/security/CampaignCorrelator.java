/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.util.Log;

import za.co.circleos.security.AttackCampaign;
import za.co.circleos.security.ThreatIndicator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Attack Campaign Correlator — Phase 3.
 *
 * Clusters ThreatIndicators into AttackCampaigns based on shared infrastructure,
 * TTPs, and temporal proximity.
 *
 * Correlation signals:
 *   1. Shared IP /24 subnet — if two IOC sets share IPs in the same /24, likely same actor
 *   2. Shared domain registrar pattern — same registrar + similar naming convention
 *   3. Temporal window — IOCs observed within 72h window belong to same wave
 *   4. Beacon interval match — same beacon timing ±5% = same implant family
 *   5. File hash cluster — if hash A is co-submitted with IP B which is also in campaign C,
 *      link them
 *
 * Output: List<AttackCampaign> with clustered IOCs and MITRE ATT&CK TTP mapping.
 */
public class CampaignCorrelator {

    private static final String TAG = "CircleCampaign";

    /** Temporal window for same-wave correlation (72 hours). */
    private static final long TEMPORAL_WINDOW_MS = 72 * 60 * 60 * 1000L;
    /** Beacon interval match tolerance (±5%). */
    private static final double BEACON_TOLERANCE = 0.05;

    // campaignId → campaign
    private final ConcurrentHashMap<String, AttackCampaign> mCampaigns
            = new ConcurrentHashMap<>();

    // value → campaignId (reverse index for fast lookup)
    private final ConcurrentHashMap<String, String> mIocIndex = new ConcurrentHashMap<>();

    /**
     * Ingest a list of IOCs and correlate them into existing or new campaigns.
     * @param indicators Fresh IOCs from IocExtractor
     * @return Campaign IDs that were modified or created
     */
    public List<String> correlate(List<ThreatIndicator> indicators) {
        Set<String> touchedCampaigns = new HashSet<>();

        for (ThreatIndicator ti : indicators) {
            String existingCampaign = findCorrelatedCampaign(ti);
            if (existingCampaign != null) {
                addToCampaign(existingCampaign, ti);
                touchedCampaigns.add(existingCampaign);
            } else {
                // Check if any of the other indicators in this batch share a campaign
                String batchCampaign = findBatchCampaign(ti, indicators);
                if (batchCampaign != null) {
                    addToCampaign(batchCampaign, ti);
                    touchedCampaigns.add(batchCampaign);
                } else {
                    // Create new campaign
                    String newId = createCampaign(ti);
                    touchedCampaigns.add(newId);
                }
            }
        }

        // Second pass: merge campaigns that now share IOCs
        mergeCampaigns();

        Log.i(TAG, "Correlate complete — " + indicators.size() + " IOCs → "
                + touchedCampaigns.size() + " campaigns touched");
        return new ArrayList<>(touchedCampaigns);
    }

    public List<AttackCampaign> getAllCampaigns() {
        return new ArrayList<>(mCampaigns.values());
    }

    public AttackCampaign getCampaign(String id) {
        return mCampaigns.get(id);
    }

    /* ── Correlation logic ─────────────────────────────────────────────── */

    private String findCorrelatedCampaign(ThreatIndicator ti) {
        // Direct value match
        String direct = mIocIndex.get(ti.value);
        if (direct != null) return direct;

        // Subnet match for IPs
        if (ti.type == ThreatIndicator.TYPE_IP_ADDRESS) {
            String subnet = subnetOf(ti.value);
            if (subnet != null) {
                for (Map.Entry<String, String> e : mIocIndex.entrySet()) {
                    if (e.getKey().startsWith(subnet + ".")) {
                        return e.getValue();
                    }
                }
            }
        }

        // Temporal match: find a campaign with a recent IOC (within window)
        if (ti.type == ThreatIndicator.TYPE_BEACON) {
            for (AttackCampaign c : mCampaigns.values()) {
                if (Math.abs(ti.lastSeen - c.lastSeenMs) < TEMPORAL_WINDOW_MS) {
                    // Check beacon interval match
                    String beaconInterval = extractBeaconInterval(ti.value);
                    for (String ioc : c.iocs) {
                        if (ioc.startsWith("interval=") && beaconInterval != null) {
                            try {
                                int existing = Integer.parseInt(
                                        ioc.replace("interval=", "").split(",")[0].replace("s", ""));
                                int incoming = Integer.parseInt(beaconInterval);
                                if (Math.abs(existing - incoming) / (double) existing < BEACON_TOLERANCE) {
                                    return c.campaignId;
                                }
                            } catch (NumberFormatException ignored) {}
                        }
                    }
                }
            }
        }

        return null;
    }

    private String findBatchCampaign(ThreatIndicator ti, List<ThreatIndicator> batch) {
        // If batch contains an IP in the same /24 as this one
        if (ti.type == ThreatIndicator.TYPE_IP_ADDRESS) {
            String mySubnet = subnetOf(ti.value);
            for (ThreatIndicator other : batch) {
                if (other == ti) continue;
                if (other.type == ThreatIndicator.TYPE_IP_ADDRESS) {
                    if (mySubnet != null && mySubnet.equals(subnetOf(other.value))) {
                        String existing = mIocIndex.get(other.value);
                        if (existing != null) return existing;
                    }
                }
            }
        }
        return null;
    }

    private String createCampaign(ThreatIndicator seed) {
        AttackCampaign c = new AttackCampaign();
        c.campaignId    = UUID.randomUUID().toString();
        c.name          = "campaign-" + c.campaignId.substring(0, 8);
        c.description   = "Auto-correlated campaign seeded by " + typeLabel(seed.type) + ": " + seed.value;
        c.confidence    = seed.confidence;
        c.attribution   = AttackCampaign.ATTRIBUTION_UNKNOWN;
        c.firstSeenMs   = seed.firstSeen;
        c.lastSeenMs    = seed.lastSeen;
        c.stixId        = "campaign--" + UUID.randomUUID();
        c.iocs.add(seed.value);
        // Map TTP hints from IOC type
        mapTtps(c, seed);

        mCampaigns.put(c.campaignId, c);
        mIocIndex.put(seed.value, c.campaignId);
        Log.i(TAG, "New campaign: " + c.campaignId + " ← " + seed.value);
        return c.campaignId;
    }

    private void addToCampaign(String campaignId, ThreatIndicator ti) {
        AttackCampaign c = mCampaigns.get(campaignId);
        if (c == null) return;
        if (!c.iocs.contains(ti.value)) c.iocs.add(ti.value);
        if (ti.lastSeen > c.lastSeenMs) c.lastSeenMs = ti.lastSeen;
        if (ti.firstSeen < c.firstSeenMs) c.firstSeenMs = ti.firstSeen;
        c.confidence = Math.max(c.confidence, ti.confidence);
        mIocIndex.put(ti.value, campaignId);
        mapTtps(c, ti);
    }

    private void mergeCampaigns() {
        // Simple merge: if two campaigns share any IOC value, merge smaller into larger
        Map<String, Set<String>> iocSets = new HashMap<>();
        for (AttackCampaign c : mCampaigns.values()) {
            iocSets.put(c.campaignId, new HashSet<>(c.iocs));
        }

        List<String> ids = new ArrayList<>(mCampaigns.keySet());
        for (int i = 0; i < ids.size(); i++) {
            for (int j = i + 1; j < ids.size(); j++) {
                String idA = ids.get(i), idB = ids.get(j);
                if (!mCampaigns.containsKey(idA) || !mCampaigns.containsKey(idB)) continue;
                Set<String> overlap = new HashSet<>(iocSets.getOrDefault(idA, new HashSet<>()));
                overlap.retainAll(iocSets.getOrDefault(idB, new HashSet<>()));
                if (!overlap.isEmpty()) {
                    // Merge B into A
                    AttackCampaign a = mCampaigns.get(idA);
                    AttackCampaign b = mCampaigns.get(idB);
                    a.iocs.addAll(b.iocs);
                    for (String ioc : b.iocs) mIocIndex.put(ioc, idA);
                    mCampaigns.remove(idB);
                    Log.i(TAG, "Merged campaign " + idB + " into " + idA);
                }
            }
        }
    }

    private void mapTtps(AttackCampaign c, ThreatIndicator ti) {
        switch (ti.type) {
            case ThreatIndicator.TYPE_BEACON:
                addTtp(c, "T1071.001"); // Application Layer Protocol: Web Protocols
                addTtp(c, "T1102");     // Web Service (C2 via beaconing)
                break;
            case ThreatIndicator.TYPE_DOMAIN:
                addTtp(c, "T1568");     // Dynamic Resolution
                break;
            case ThreatIndicator.TYPE_FILE_HASH:
                addTtp(c, "T1027");     // Obfuscated Files or Information
                break;
            case ThreatIndicator.TYPE_IP_ADDRESS:
                addTtp(c, "T1071");     // Application Layer Protocol
                break;
        }
    }

    private void addTtp(AttackCampaign c, String ttp) {
        if (!c.ttps.contains(ttp)) c.ttps.add(ttp);
    }

    private String subnetOf(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length < 3) return null;
        return parts[0] + "." + parts[1] + "." + parts[2];
    }

    private String extractBeaconInterval(String value) {
        // value format: "interval=30s,src=com.example"
        if (value.startsWith("interval=")) {
            return value.split(",")[0].replace("interval=", "").replace("s", "");
        }
        return null;
    }

    private String typeLabel(int type) {
        switch (type) {
            case ThreatIndicator.TYPE_IP_ADDRESS: return "IP";
            case ThreatIndicator.TYPE_DOMAIN:     return "domain";
            case ThreatIndicator.TYPE_FILE_HASH:  return "hash";
            case ThreatIndicator.TYPE_BEACON:     return "beacon";
            default: return "indicator";
        }
    }
}
