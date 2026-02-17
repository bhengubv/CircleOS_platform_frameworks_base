/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.util.Log;

import za.co.circleos.security.DmzAnalysisResult;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * In-memory threat feed store backed by flat files.
 *
 * Feed files live in /data/circle/security/feeds/:
 *   c2_ips.txt      — one IP per line
 *   c2_domains.txt  — one domain per line
 *   malware_hashes.txt — one SHA-256 per line
 *
 * Quarantine records live in /data/circle/security/quarantine/.
 *
 * Phase 2: upgrade to sorted-set + bloom filter for millions of entries.
 */
public class ThreatFeedDatabase {

    private static final String TAG          = "CircleFileDmz.Feeds";
    private static final String FEEDS_DIR    = "/data/circle/security/feeds/";
    private static final String QUARANTINE_DIR = "/data/circle/security/quarantine/";

    private final Set<String> mBlockedIps     = Collections.synchronizedSet(new HashSet<>());
    private final Set<String> mBlockedDomains = Collections.synchronizedSet(new HashSet<>());
    private final Set<String> mBlockedHashes  = Collections.synchronizedSet(new HashSet<>());

    // Quarantine: sessionId → DmzAnalysisResult
    private final java.util.concurrent.ConcurrentHashMap<String, DmzAnalysisResult> mQuarantine
            = new java.util.concurrent.ConcurrentHashMap<>();

    public ThreatFeedDatabase() {
        reload();
    }

    public boolean isIpBlocked(String ip) {
        return ip != null && mBlockedIps.contains(ip.trim());
    }

    public boolean isDomainBlocked(String domain) {
        return domain != null && mBlockedDomains.contains(domain.trim().toLowerCase());
    }

    public boolean isHashBlocked(String sha256) {
        return sha256 != null && mBlockedHashes.contains(sha256.trim().toLowerCase());
    }

    public void addToQuarantine(DmzAnalysisResult result) {
        mQuarantine.put(result.sessionId, result);
    }

    public List<DmzAnalysisResult> listQuarantined() {
        return new ArrayList<>(mQuarantine.values());
    }

    public void deleteQuarantined(String sessionId) {
        mQuarantine.remove(sessionId);
    }

    public synchronized void reload() {
        mBlockedIps.clear();
        mBlockedDomains.clear();
        mBlockedHashes.clear();
        loadSet(FEEDS_DIR + "c2_ips.txt",         mBlockedIps);
        loadSet(FEEDS_DIR + "c2_domains.txt",      mBlockedDomains);
        loadSet(FEEDS_DIR + "malware_hashes.txt",  mBlockedHashes);
        Log.i(TAG, "Feeds loaded: " + mBlockedIps.size() + " IPs, "
                + mBlockedDomains.size() + " domains, "
                + mBlockedHashes.size() + " hashes");
    }

    private void loadSet(String path, Set<String> target) {
        File f = new File(path);
        if (!f.exists()) return;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim().toLowerCase();
                if (!line.isEmpty() && !line.startsWith("#")) target.add(line);
            }
        } catch (IOException e) {
            Log.w(TAG, "Cannot read " + path + ": " + e.getMessage());
        }
    }
}
