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

    /**
     * Seed list of ASNs with documented history of hosting C2 infrastructure,
     * bulletproof hosting, or high abuse rates. Sourced from public threat
     * intelligence (Spamhaus ASN-DROP, AbuseIPDB ASN stats, public CTI reports).
     *
     * Phase 4: supplement this static list by pulling ASN-DROP from Data Acuity
     * API on a 24-hour refresh cycle.
     */
    private static final Set<String> KNOWN_BAD_ASNS = new HashSet<>(java.util.Arrays.asList(
        // Bulletproof hosters with documented abuse
        "AS3842",   // RACKDOG-AS — repeatedly used for C2 / botnet infrastructure
        "AS49581",  // Ferdinand Zink (TUBK) — bulletproof host, RU
        "AS197068", // QWARTA LLC — bulletproof, RU
        "AS206485", // MAFF LLC — frequent C2 hoster
        "AS59795",  // Hostmaster Ltd — known spam/C2 host
        "AS60117",  // Makonix SIA — LV bulletproof
        "AS35624",  // EnterHost UA — bulletproof, Ukraine
        "AS8283",   // Alexhost SRL MD — abused for botnet C2
        "AS209854", // Nybula Ltd — bulletproof UK
        "AS196892", // Delis LLC — Russia, bulletproof
        "AS12586",  // GHOSTnet GmbH — RU transit, abuse-heavy
        "AS43260",  // DGN Teknoloji (Turkey) — bulletproof
        "AS9002",   // RETN Limited — used as C2 transit
        "AS52019",  // Internet Free Zone — Russia, C2 hosting
        "AS210320", // Alibek Omarov — KZ bulletproof
        "AS48031",  // Yulia Cher — RU bulletproof
        "AS197555", // Layer-6 Networks — UK bulletproof
        "AS13213",  // UK2NET-AS — historically abused VPS provider
        "AS197414", // Medyabim Internet Hizmetleri — TR bulletproof
        "AS49544",  // i3D.net — mixed, used in high-profile DDoS campaigns
        "AS42831",  // UK Dedicated Servers — frequently abused
        "AS34665",  // Petersburg Internet Network — RU spam/C2
        "AS43289",  // Telehandel — DE bulletproof
        "AS47869",  // Netrouting B.V. — NL, C2-heavy
        "AS204428"  // SS-Net — Ukraine bulletproof
    ));

    // ip → ASN (e.g. "AS12345")
    private final ConcurrentHashMap<String, String> mIpAsnMap
            = new ConcurrentHashMap<>();
    // ASN → set of IPs seen in that ASN
    private final ConcurrentHashMap<String, Set<String>> mAsnIpMap
            = new ConcurrentHashMap<>();

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

    /**
     * Add a known-bad IP with its ASN. If the ASN is in KNOWN_BAD_ASNS the
     * IP is flagged for elevated priority in future threat scoring.
     *
     * @param ip         IPv4 address
     * @param asn        ASN string in "AS12345" format, or null if unknown
     * @param campaignId Campaign this IP belongs to
     * @return true if the ASN was in the known-bad set
     */
    public boolean addIpWithAsn(String ip, String asn, String campaignId) {
        addIp(ip, campaignId);
        if (asn != null && !asn.isEmpty()) {
            mIpAsnMap.put(ip, asn);
            mAsnIpMap.computeIfAbsent(asn, k -> new HashSet<>()).add(ip);
            if (KNOWN_BAD_ASNS.contains(asn)) {
                Log.w(TAG, "IP " + ip + " in known-bad ASN " + asn
                        + " (campaign=" + campaignId + ")");
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true if the given ASN is in the known-bad seed list.
     * Can be used by calling code to elevate threat confidence before
     * storing a ThreatIndicator.
     */
    public boolean isKnownBadAsn(String asn) {
        return asn != null && KNOWN_BAD_ASNS.contains(asn);
    }

    /**
     * Returns all IPs seen in a given ASN across all campaigns.
     * Useful for lateral infrastructure discovery.
     */
    public List<String> getIpsByAsn(String asn) {
        Set<String> ips = mAsnIpMap.get(asn);
        return ips != null ? new ArrayList<>(ips) : new ArrayList<>();
    }

    /**
     * Adds the KNOWN_BAD_ASNS set entries from an external feed update.
     * Phase 4: called by DataAcuityClient on receipt of ASN-DROP feed.
     */
    public void ingestBadAsnFeed(List<String> asnList) {
        if (asnList == null || asnList.isEmpty()) return;
        int added = 0;
        for (String asn : asnList) {
            if (asn != null && !asn.isEmpty() && KNOWN_BAD_ASNS.add(asn)) added++;
        }
        Log.i(TAG, "ingestBadAsnFeed: added " + added + " new ASNs (total="
                + KNOWN_BAD_ASNS.size() + ")");
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
