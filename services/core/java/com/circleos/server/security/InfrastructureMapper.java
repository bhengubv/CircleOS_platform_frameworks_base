/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.util.Log;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Threat Infrastructure Mapper — Phase 3.
 *
 * Builds and queries the "Zombie Map" — a graph of related threat infrastructure.
 *
 * Infrastructure graph nodes:
 *   - IP addresses → /24 subnet cluster → ASN bucket
 *   - Domains → registrar group → nameserver cluster
 *
 * Edges:
 *   - Same /24 subnet → RELATED_SUBNET
 *   - Same nameserver set → RELATED_NAMESERVER
 *   - Co-observed in same campaign → CO_CAMPAIGN
 *   - Temporal proximity (within 7 days) → TEMPORAL
 *
 * Infrastructure prediction ("Zombie Maps"):
 *   If actor controls 3+ IPs in a /24, predict rest of /24 as likely infrastructure.
 *   If actor uses a specific registrar pattern (DGA subdomain of .tk/.ml/.cf),
 *   generate candidate domains based on observed patterns.
 *
 * Phase 3 implementation: in-memory graph + flat ASN map.
 * Phase 4: integrate with RIPE/ARIN ASN API and passive DNS.
 */
public class InfrastructureMapper {

    private static final String TAG = "CircleInfra";

    /** Minimum IPs in a /24 before we predict the whole subnet. */
    private static final int SUBNET_PREDICTION_THRESHOLD = 3;

    /** known-bad ASN ranges (populated from Data Acuity feeds in Phase 4). */
    private static final Set<String> KNOWN_BAD_ASNS = new HashSet<>();

    // subnet (/24) → set of known-bad IPs in that subnet
    private final ConcurrentHashMap<String, Set<String>> mSubnetMap
            = new ConcurrentHashMap<>();
    // domain → set of nameservers
    private final ConcurrentHashMap<String, Set<String>> mDomainNsMap
            = new ConcurrentHashMap<>();
    // nameserver → set of domains using it
    private final ConcurrentHashMap<String, Set<String>> mNsDomainsMap
            = new ConcurrentHashMap<>();
    // ip → campaignIds
    private final ConcurrentHashMap<String, Set<String>> mIpCampaigns
            = new ConcurrentHashMap<>();
    // domain → campaignIds
    private final ConcurrentHashMap<String, Set<String>> mDomainCampaigns
            = new ConcurrentHashMap<>();

    /**
     * Add a known-bad IP to the infrastructure graph.
     * @param ip       IPv4 address
     * @param campaignId Campaign this IP belongs to
     */
    public void addIp(String ip, String campaignId) {
        String subnet = subnetOf(ip);
        if (subnet == null) return;

        mSubnetMap.computeIfAbsent(subnet, k -> new HashSet<>()).add(ip);
        mIpCampaigns.computeIfAbsent(ip, k -> new HashSet<>()).add(campaignId);
        Log.d(TAG, "Added IP " + ip + " → " + campaignId);
    }

    /**
     * Add a known-bad domain to the infrastructure graph.
     * @param domain     Fully-qualified domain name
     * @param nameservers Nameservers for this domain (can be null/empty)
     * @param campaignId Campaign this domain belongs to
     */
    public void addDomain(String domain, List<String> nameservers, String campaignId) {
        mDomainCampaigns.computeIfAbsent(domain, k -> new HashSet<>()).add(campaignId);
        if (nameservers != null) {
            Set<String> nsSet = mDomainNsMap.computeIfAbsent(domain, k -> new HashSet<>());
            nsSet.addAll(nameservers);
            for (String ns : nameservers) {
                mNsDomainsMap.computeIfAbsent(ns, k -> new HashSet<>()).add(domain);
            }
        }
    }

    /**
     * Get known related infrastructure for a given IP or domain.
     * Returns a list of related IPs/domains.
     */
    public List<String> getRelated(String ipOrDomain) {
        Set<String> related = new HashSet<>();

        if (isIp(ipOrDomain)) {
            // Subnet siblings
            String subnet = subnetOf(ipOrDomain);
            if (subnet != null) {
                Set<String> subnetIps = mSubnetMap.get(subnet);
                if (subnetIps != null) related.addAll(subnetIps);
            }
            // Co-campaign domains
            Set<String> campaigns = mIpCampaigns.get(ipOrDomain);
            if (campaigns != null) {
                for (String cId : campaigns) {
                    for (Map.Entry<String, Set<String>> e : mDomainCampaigns.entrySet()) {
                        if (e.getValue().contains(cId)) related.add(e.getKey());
                    }
                }
            }
        } else {
            // Nameserver siblings (same NS → related domains)
            Set<String> ns = mDomainNsMap.get(ipOrDomain);
            if (ns != null) {
                for (String nameserver : ns) {
                    Set<String> siblings = mNsDomainsMap.get(nameserver);
                    if (siblings != null) related.addAll(siblings);
                }
            }
            // Co-campaign IPs
            Set<String> campaigns = mDomainCampaigns.get(ipOrDomain);
            if (campaigns != null) {
                for (String cId : campaigns) {
                    for (Map.Entry<String, Set<String>> e : mIpCampaigns.entrySet()) {
                        if (e.getValue().contains(cId)) related.add(e.getKey());
                    }
                }
            }
        }

        related.remove(ipOrDomain);
        return new ArrayList<>(related);
    }

    /**
     * Predict likely related infrastructure for a campaign.
     * Uses subnet majority rule and nameserver clustering.
     */
    public List<String> predictRelated(String campaignId) {
        Set<String> predicted = new HashSet<>();

        // Collect all IPs in this campaign
        Set<String> campaignIps = new HashSet<>();
        for (Map.Entry<String, Set<String>> e : mIpCampaigns.entrySet()) {
            if (e.getValue().contains(campaignId)) campaignIps.add(e.getKey());
        }

        // Group by /24 subnet
        Map<String, Set<String>> subnetGroups = new HashMap<>();
        for (String ip : campaignIps) {
            String subnet = subnetOf(ip);
            if (subnet != null) subnetGroups.computeIfAbsent(subnet, k -> new HashSet<>()).add(ip);
        }

        // If a subnet has >= threshold IPs, predict the rest of the /24
        for (Map.Entry<String, Set<String>> e : subnetGroups.entrySet()) {
            if (e.getValue().size() >= SUBNET_PREDICTION_THRESHOLD) {
                String subnet = e.getKey();
                // Add the subnet range as a prediction note
                predicted.add(subnet + ".0/24 (predicted — " + e.getValue().size()
                        + " confirmed IPs in this /24)");
                Log.i(TAG, "Predicted /24 subnet: " + subnet + ".0/24 for campaign " + campaignId);
            }
        }

        // Nameserver-based domain prediction
        Set<String> campaignDomains = new HashSet<>();
        for (Map.Entry<String, Set<String>> e : mDomainCampaigns.entrySet()) {
            if (e.getValue().contains(campaignId)) campaignDomains.add(e.getKey());
        }

        Set<String> campaignNs = new HashSet<>();
        for (String d : campaignDomains) {
            Set<String> ns = mDomainNsMap.get(d);
            if (ns != null) campaignNs.addAll(ns);
        }

        // All domains sharing a nameserver with this campaign are candidates
        for (String ns : campaignNs) {
            Set<String> nsDomains = mNsDomainsMap.get(ns);
            if (nsDomains != null) {
                for (String d : nsDomains) {
                    if (!campaignDomains.contains(d)) {
                        predicted.add(d + " (predicted — shared NS: " + ns + ")");
                    }
                }
            }
        }

        return new ArrayList<>(predicted);
    }

    /** Populate from campaign correlator output. */
    public void ingestCampaigns(List<za.co.circleos.security.AttackCampaign> campaigns) {
        for (za.co.circleos.security.AttackCampaign c : campaigns) {
            for (String ioc : c.iocs) {
                if (isIp(ioc)) {
                    addIp(ioc, c.campaignId);
                } else {
                    addDomain(ioc, null, c.campaignId);
                }
            }
        }
        Log.i(TAG, "Ingested " + campaigns.size() + " campaigns into infrastructure graph");
    }

    private boolean isIp(String s) {
        return s.matches("\\d{1,3}(\\.\\d{1,3}){3}.*");
    }

    private String subnetOf(String ip) {
        String[] parts = ip.split("[.:]")[0].split("\\.");
        if (parts.length < 3) return null;
        return parts[0] + "." + parts[1] + "." + parts[2];
    }
}
