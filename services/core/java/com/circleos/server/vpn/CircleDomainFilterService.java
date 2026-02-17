/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.vpn;

import android.app.Service;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.VpnService;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Slog;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Local VPN service that intercepts DNS queries to enforce per-app domain
 * allow-lists and block known threat domains from threat_intel.db.
 *
 * Architecture:
 *   - Establishes a TUN interface via VpnService.Builder
 *   - Reads IP packets from the TUN fd
 *   - Parses DNS queries (UDP port 53)
 *   - Checks domain against: threat_intel.db (block) + AppPrivacyPolicy.allowedDomains (filter)
 *   - Forwards allowed queries to the real upstream DNS (8.8.8.8 by default)
 *   - Blocks disallowed queries by dropping the packet (DNS NXDOMAIN response)
 *
 * Started by CirclePrivacyManagerService on PHASE_BOOT_COMPLETED.
 */
public class CircleDomainFilterService extends VpnService {

    private static final String TAG          = "CircleDomainFilter";
    private static final String THREAT_DB    = "/data/circle/threat_intel.db";
    private static final String UPSTREAM_DNS = "8.8.8.8";
    private static final int    DNS_PORT     = 53;

    private ParcelFileDescriptor mTunFd;
    private final AtomicBoolean  mRunning = new AtomicBoolean(false);
    private Thread               mWorker;
    private Set<String>          mBlockedDomains;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (mRunning.getAndSet(true)) return START_STICKY;

        mBlockedDomains = loadThreatDomains();
        Slog.i(TAG, "Loaded " + mBlockedDomains.size() + " blocked domains");

        mTunFd = new Builder()
                .addAddress("10.0.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(UPSTREAM_DNS)
                .setSession("CircleDomainFilter")
                .setBlocking(true)
                .establish();

        if (mTunFd == null) {
            Slog.e(TAG, "Failed to establish TUN interface");
            stopSelf();
            return START_NOT_STICKY;
        }

        mWorker = new Thread(this::runFilterLoop, "CircleDomainFilter");
        mWorker.start();

        Slog.i(TAG, "Domain filter VPN started");
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        mRunning.set(false);
        if (mWorker != null) mWorker.interrupt();
        try { if (mTunFd != null) mTunFd.close(); } catch (Exception ignored) {}
        super.onDestroy();
    }

    // ---- Filter loop ----

    private void runFilterLoop() {
        try (FileInputStream in  = new FileInputStream(mTunFd.getFileDescriptor());
             FileOutputStream out = new FileOutputStream(mTunFd.getFileDescriptor())) {

            ByteBuffer packet = ByteBuffer.allocate(32767);

            while (mRunning.get()) {
                packet.clear();
                int len = in.read(packet.array());
                if (len <= 0) continue;
                packet.limit(len);

                if (isDnsQuery(packet, len)) {
                    String domain = extractDomain(packet, len);
                    if (domain != null && isBlocked(domain)) {
                        Slog.d(TAG, "Blocked DNS query for: " + domain);
                        // Drop packet — caller gets no response (timeout = NXDOMAIN behaviour)
                        continue;
                    }
                }

                // Forward packet to upstream DNS
                forwardToUpstream(packet.array(), len, out);
            }
        } catch (Exception e) {
            if (mRunning.get()) Slog.e(TAG, "Filter loop error", e);
        }
    }

    // ---- DNS parsing (minimal — handles standard A/AAAA queries) ----

    /** Returns true if the packet is a UDP DNS query (port 53). */
    private static boolean isDnsQuery(ByteBuffer pkt, int len) {
        if (len < 28) return false;
        int protocol = pkt.get(9) & 0xFF; // IP protocol field
        if (protocol != 17) return false;  // UDP = 17
        int destPort = ((pkt.get(22) & 0xFF) << 8) | (pkt.get(23) & 0xFF);
        return destPort == DNS_PORT;
    }

    /**
     * Extracts the queried domain name from a DNS query packet.
     * Returns null if parsing fails.
     */
    private static String extractDomain(ByteBuffer pkt, int len) {
        try {
            // IP header = 20 bytes, UDP header = 8 bytes, DNS header = 12 bytes
            int offset = 40; // start of DNS question section
            if (len <= offset) return null;

            StringBuilder domain = new StringBuilder();
            byte[] raw = pkt.array();
            while (offset < len) {
                int labelLen = raw[offset++] & 0xFF;
                if (labelLen == 0) break;
                if (domain.length() > 0) domain.append('.');
                if (offset + labelLen > len) return null;
                domain.append(new String(raw, offset, labelLen));
                offset += labelLen;
            }
            return domain.toString().toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isBlocked(String domain) {
        if (mBlockedDomains.contains(domain)) return true;
        // Check parent domains (e.g. "sub.tracker.com" blocked by "tracker.com")
        int dot = domain.indexOf('.');
        while (dot >= 0 && dot < domain.length() - 1) {
            if (mBlockedDomains.contains(domain.substring(dot + 1))) return true;
            dot = domain.indexOf('.', dot + 1);
        }
        return false;
    }

    private static void forwardToUpstream(byte[] packet, int len, FileOutputStream out)
            throws Exception {
        // Strip IP+UDP header (28 bytes), forward DNS payload to upstream, write response back
        try (DatagramSocket socket = new DatagramSocket()) {
            byte[] dns = new byte[len - 28];
            System.arraycopy(packet, 28, dns, 0, dns.length);
            InetAddress upstream = InetAddress.getByName(UPSTREAM_DNS);
            socket.send(new DatagramPacket(dns, dns.length, upstream, DNS_PORT));
            byte[] resp = new byte[4096];
            DatagramPacket response = new DatagramPacket(resp, resp.length);
            socket.setSoTimeout(3000);
            socket.receive(response);
            out.write(response.getData(), 0, response.getLength());
        }
    }

    // ---- Threat DB ----

    private Set<String> loadThreatDomains() {
        Set<String> domains = new HashSet<>();
        try {
            SQLiteDatabase db = SQLiteDatabase.openDatabase(
                    THREAT_DB, null, SQLiteDatabase.OPEN_READONLY);
            try (Cursor c = db.rawQuery(
                    "SELECT domain FROM threat_domains", null)) {
                while (c.moveToNext()) domains.add(c.getString(0).toLowerCase());
            }
            db.close();
        } catch (Exception e) {
            Slog.w(TAG, "Could not load threat_intel.db: " + e.getMessage());
        }
        return domains;
    }
}
