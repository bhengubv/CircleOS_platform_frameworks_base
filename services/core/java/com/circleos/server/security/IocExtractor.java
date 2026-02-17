/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.util.Log;

import za.co.circleos.security.DmzAnalysisResult;
import za.co.circleos.security.QuarantineRecord;
import za.co.circleos.security.ThreatIndicator;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Automated IOC Extractor — Phase 3.
 *
 * Produces structured ThreatIndicator objects from raw analysis output.
 * Sources:
 *   - DmzAnalysisResult (from CircleFileDmzService + BehavioralSandbox)
 *   - QuarantineRecord
 *   - Traffic Lobby connection records (future hook)
 *
 * Output feeds:
 *   - CampaignCorrelator (local clustering)
 *   - CommunityDefenseService (anonymized submission)
 *   - DataAcuityClient (researcher API)
 *
 * IOC types produced: IP_ADDRESS, DOMAIN, FILE_HASH, TLS_FP, BEACON
 *
 * STIX 2.1 export: toStixIndicator() on each ThreatIndicator (appended by
 * ResearcherApiService when building IocBundle).
 */
public class IocExtractor {

    private static final String TAG = "CircleIOC";

    private static final Pattern IPV4 = Pattern.compile(
            "\\b((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b");
    private static final Pattern DOMAIN = Pattern.compile(
            "\\b([a-z0-9][a-z0-9\\-]{0,61}[a-z0-9]\\.)+([a-z]{2,})\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SHA256 = Pattern.compile(
            "\\b[0-9a-f]{64}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern BEACON_LABEL = Pattern.compile(
            "interval\\s*~(\\d+)s", Pattern.CASE_INSENSITIVE);

    /** Extract all IOCs from a completed DMZ analysis result. */
    public List<ThreatIndicator> extractFromDmzResult(DmzAnalysisResult result) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        long now = System.currentTimeMillis();

        // File hash
        if (result.sha256 != null && !result.sha256.isEmpty()) {
            indicators.add(makeIndicator(
                    ThreatIndicator.TYPE_FILE_HASH, result.sha256,
                    confidenceFor(result.verdict), "dmz", now));
        }

        // C2 addresses (extracted by BehavioralSandbox)
        for (String addr : result.c2Addresses) {
            if (isIpv4(addr)) {
                indicators.add(makeIndicator(ThreatIndicator.TYPE_IP_ADDRESS, addr,
                        confidenceFor(result.verdict), "behavioral", now));
            } else if (looksLikeDomain(addr)) {
                indicators.add(makeIndicator(ThreatIndicator.TYPE_DOMAIN, addr,
                        confidenceFor(result.verdict), "behavioral", now));
            }
        }

        // Parse free-text findings for any additional IOCs
        for (String finding : result.findings) {
            extractFromText(finding, indicators, "finding", now,
                    confidenceFor(result.verdict));
        }

        Log.i(TAG, "Extracted " + indicators.size() + " IOCs from DMZ result: " + result.sessionId);
        return indicators;
    }

    /** Extract all IOCs from a quarantine record. */
    public List<ThreatIndicator> extractFromQuarantine(QuarantineRecord record) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        long now = System.currentTimeMillis();

        if (record.sha256 != null) {
            indicators.add(makeIndicator(ThreatIndicator.TYPE_FILE_HASH, record.sha256,
                    ThreatIndicator.CONFIDENCE_HIGH, "quarantine", now));
        }

        for (String ioc : record.iocExtracted) {
            if (ioc.startsWith("BEHAVIORAL:") || ioc.startsWith("CDR:")) continue;
            if (isIpv4(ioc)) {
                indicators.add(makeIndicator(ThreatIndicator.TYPE_IP_ADDRESS, ioc,
                        ThreatIndicator.CONFIDENCE_MEDIUM, "quarantine", now));
            } else if (looksLikeDomain(ioc)) {
                indicators.add(makeIndicator(ThreatIndicator.TYPE_DOMAIN, ioc,
                        ThreatIndicator.CONFIDENCE_MEDIUM, "quarantine", now));
            }
        }

        // Check for beacon pattern in threat name
        if (record.threatName != null) {
            Matcher m = BEACON_LABEL.matcher(record.threatName);
            if (m.find()) {
                ThreatIndicator beacon = makeIndicator(ThreatIndicator.TYPE_BEACON,
                        "interval=" + m.group(1) + "s,src=" + record.sourceApp,
                        ThreatIndicator.CONFIDENCE_MEDIUM, "quarantine", now);
                beacon.description = "Beacon from " + record.sourceApp
                        + " at ~" + m.group(1) + "s intervals";
                indicators.add(beacon);
            }
        }

        Log.i(TAG, "Extracted " + indicators.size() + " IOCs from quarantine: " + record.quarantineId);
        return indicators;
    }

    /**
     * Convert a ThreatIndicator to a STIX 2.1 indicator JSON object (string).
     * The caller appends this into the "objects" array of a STIX bundle.
     */
    public String toStixIndicator(ThreatIndicator ti) {
        String stixId = "indicator--" + java.util.UUID.randomUUID();
        String pattern = stixPatternFor(ti);
        String type = stixTypeFor(ti);
        String created = isoNow();

        return String.format(
            "{\"type\":\"indicator\","
            + "\"id\":\"%s\","
            + "\"spec_version\":\"2.1\","
            + "\"created\":\"%s\","
            + "\"modified\":\"%s\","
            + "\"indicator_types\":[\"%s\"],"
            + "\"pattern\":\"%s\","
            + "\"pattern_type\":\"stix\","
            + "\"valid_from\":\"%s\","
            + "\"confidence\":%d,"
            + "\"labels\":[\"circleos\"]}",
            stixId, created, created, type,
            escapeJson(pattern), created,
            ti.confidence * 33);
    }

    /* ── Helpers ──────────────────────────────────────────────────────── */

    private void extractFromText(String text, List<ThreatIndicator> out,
                                  String source, long now, int confidence) {
        Matcher ipM = IPV4.matcher(text);
        while (ipM.find()) {
            String ip = ipM.group();
            if (!ip.startsWith("127.") && !ip.startsWith("10.")
                    && !ip.startsWith("192.168")) {
                out.add(makeIndicator(ThreatIndicator.TYPE_IP_ADDRESS, ip, confidence, source, now));
            }
        }
        Matcher hashM = SHA256.matcher(text);
        while (hashM.find()) {
            out.add(makeIndicator(ThreatIndicator.TYPE_FILE_HASH, hashM.group().toLowerCase(),
                    confidence, source, now));
        }
    }

    private ThreatIndicator makeIndicator(int type, String value, int confidence,
                                          String source, long now) {
        ThreatIndicator ti = new ThreatIndicator();
        ti.type        = type;
        ti.value       = value;
        ti.confidence  = confidence;
        ti.source      = source;
        ti.firstSeen   = now;
        ti.lastSeen    = now;
        return ti;
    }

    private int confidenceFor(int verdict) {
        switch (verdict) {
            case DmzAnalysisResult.VERDICT_THREAT:    return ThreatIndicator.CONFIDENCE_HIGH;
            case DmzAnalysisResult.VERDICT_SUSPICIOUS: return ThreatIndicator.CONFIDENCE_MEDIUM;
            default: return ThreatIndicator.CONFIDENCE_LOW;
        }
    }

    private boolean isIpv4(String s) {
        return IPV4.matcher(s.split(":")[0]).matches();
    }

    private boolean looksLikeDomain(String s) {
        return DOMAIN.matcher(s).matches() && s.contains(".");
    }

    private String stixPatternFor(ThreatIndicator ti) {
        switch (ti.type) {
            case ThreatIndicator.TYPE_IP_ADDRESS:
                return "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '"
                        + ti.value + "']";
            case ThreatIndicator.TYPE_DOMAIN:
                return "[domain-name:value = '" + ti.value + "']";
            case ThreatIndicator.TYPE_FILE_HASH:
                return "[file:hashes.'SHA-256' = '" + ti.value + "']";
            case ThreatIndicator.TYPE_BEACON:
                return "[network-traffic:extensions.'http-request-ext'.request_header.'X-Beacon' IS NOT NULL]";
            default:
                return "[artifact:payload_bin IS NOT NULL]";
        }
    }

    private String stixTypeFor(ThreatIndicator ti) {
        switch (ti.type) {
            case ThreatIndicator.TYPE_IP_ADDRESS: return "malicious-activity";
            case ThreatIndicator.TYPE_DOMAIN:     return "malicious-activity";
            case ThreatIndicator.TYPE_FILE_HASH:  return "malware";
            case ThreatIndicator.TYPE_BEACON:     return "malware-behavior";
            default: return "unknown";
        }
    }

    private String isoNow() {
        return new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .format(new java.util.Date());
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'");
    }
}
