package com.circleos.server.vpn;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.URL;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;

/**
 * CircleOS Domain Filter Service
 *
 * VPN-based DNS interception with DNS-over-HTTPS (DoH) support.
 *
 * - Intercepts all DNS queries (UDP port 53) via TUN interface
 * - Blocks queries to domains in the threat intel database (NXDOMAIN response)
 * - Forwards allowed queries via DoH to Quad9 (https://dns.quad9.net/dns-query)
 *   preventing ISP DNS surveillance and DNS-based tracking
 * - Falls back to Cloudflare DoH, then plaintext DNS if both DoH endpoints fail
 * - All DoH uses RFC 8484 application/dns-message wire format
 */
public class CircleDomainFilterService extends VpnService {

    private static final String TAG = "CircleDomainFilter";

    // Primary DoH: Quad9 — privacy-first, no logging, DNSSEC validated
    private static final String DOH_PRIMARY  = "https://dns.quad9.net/dns-query";
    // Secondary DoH: Cloudflare — fallback only
    private static final String DOH_FALLBACK = "https://cloudflare-dns.com/dns-query";
    // Plaintext last resort
    private static final String FALLBACK_DNS = "9.9.9.9";

    private static final int DNS_PORT    = 53;
    private static final int DOH_TIMEOUT = 5000; // ms

    private ParcelFileDescriptor mInterface;
    private ExecutorService mExecutor;
    private volatile boolean mRunning;
    private final Set<String> mBlockedDomains = ConcurrentHashMap.newKeySet();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        mExecutor = Executors.newCachedThreadPool();
        mRunning = true;
        loadThreatDomains();
        establish();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        mRunning = false;
        if (mExecutor != null) mExecutor.shutdownNow();
        if (mInterface != null) {
            try { mInterface.close(); } catch (IOException ignored) {}
        }
    }

    private void loadThreatDomains() {
        try {
            android.database.sqlite.SQLiteDatabase db =
                android.database.sqlite.SQLiteDatabase.openDatabase(
                    "/data/circle/threat_intel.db", null,
                    android.database.sqlite.SQLiteDatabase.OPEN_READONLY);
            android.database.Cursor c = db.rawQuery(
                "SELECT domain FROM threat_domains", null);
            while (c.moveToNext()) {
                mBlockedDomains.add(c.getString(0).toLowerCase());
            }
            c.close();
            db.close();
            Log.i(TAG, "Loaded " + mBlockedDomains.size() + " blocked domains");
        } catch (Exception e) {
            Log.w(TAG, "Could not load threat domains: " + e.getMessage());
        }
    }

    private void establish() {
        try {
            mInterface = new Builder()
                .addAddress("10.0.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(FALLBACK_DNS)
                .setSession("CircleDomainFilter")
                .establish();

            if (mInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface");
                return;
            }
            mExecutor.execute(this::processPackets);
            Log.i(TAG, "CircleDomainFilterService established (DoH: " + DOH_PRIMARY + ")");
        } catch (Exception e) {
            Log.e(TAG, "Failed to establish VPN", e);
        }
    }

    private void processPackets() {
        FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());
        byte[] buffer = new byte[32767];

        while (mRunning) {
            try {
                int len = in.read(buffer);
                if (len <= 0) continue;

                if (isDnsQuery(buffer, len)) {
                    String domain = extractDomain(buffer, len);
                    if (domain != null && isBlocked(domain)) {
                        Log.d(TAG, "Blocked DNS query for: " + domain);
                        sendNxDomain(out, buffer, len);
                    } else {
                        byte[] dnsPayload = extractDnsPayload(buffer, len);
                        if (dnsPayload != null) {
                            byte[] pktCopy = new byte[len];
                            System.arraycopy(buffer, 0, pktCopy, 0, len);
                            mExecutor.execute(() -> {
                                byte[] response = queryDoH(dnsPayload);
                                if (response != null) {
                                    try {
                                        out.write(wrapInIpUdp(response, pktCopy, pktCopy.length));
                                    } catch (IOException ignored) {}
                                }
                            });
                        }
                    }
                } else {
                    out.write(buffer, 0, len);
                }
            } catch (IOException e) {
                if (mRunning) Log.e(TAG, "Packet processing error", e);
            }
        }
    }

    /**
     * Send DNS query via DNS-over-HTTPS (RFC 8484 wire format).
     * Tries Quad9, then Cloudflare, then plaintext UDP as last resort.
     */
    private byte[] queryDoH(byte[] dnsQuery) {
        for (String endpoint : new String[]{DOH_PRIMARY, DOH_FALLBACK}) {
            try {
                URL url = new URL(endpoint);
                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/dns-message");
                conn.setRequestProperty("Accept", "application/dns-message");
                conn.setConnectTimeout(DOH_TIMEOUT);
                conn.setReadTimeout(DOH_TIMEOUT);
                conn.setDoOutput(true);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(dnsQuery);
                }

                if (conn.getResponseCode() == 200) {
                    return conn.getInputStream().readAllBytes();
                }
                Log.w(TAG, endpoint + " returned HTTP " + conn.getResponseCode());
            } catch (Exception e) {
                Log.w(TAG, "DoH failed for " + endpoint + ": " + e.getMessage());
            }
        }
        Log.w(TAG, "All DoH endpoints failed — falling back to plaintext DNS");
        return queryPlaintext(dnsQuery);
    }

    private byte[] queryPlaintext(byte[] dnsQuery) {
        try (DatagramSocket socket = new DatagramSocket()) {
            protect(socket);
            InetAddress server = InetAddress.getByName(FALLBACK_DNS);
            socket.send(new DatagramPacket(dnsQuery, dnsQuery.length, server, DNS_PORT));
            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            socket.setSoTimeout(3000);
            socket.receive(resp);
            byte[] result = new byte[resp.getLength()];
            System.arraycopy(buf, 0, result, 0, resp.getLength());
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Plaintext DNS also failed: " + e.getMessage());
            return null;
        }
    }

    private boolean isBlocked(String domain) {
        if (mBlockedDomains.contains(domain)) return true;
        // Check parent domains: sub.blocked.com → blocked.com
        String[] parts = domain.split("\\.");
        for (int i = 1; i < parts.length - 1; i++) {
            StringBuilder parent = new StringBuilder();
            for (int j = i; j < parts.length; j++) {
                if (j > i) parent.append('.');
                parent.append(parts[j]);
            }
            if (mBlockedDomains.contains(parent.toString())) return true;
        }
        return false;
    }

    // DNS/IP wire format helpers

    private boolean isDnsQuery(byte[] pkt, int len) {
        if (len < 28) return false;
        int ipHeaderLen = (pkt[0] & 0x0F) * 4;
        if (pkt[9] != 17) return false; // Must be UDP
        int dstPort = ((pkt[ipHeaderLen + 2] & 0xFF) << 8) | (pkt[ipHeaderLen + 3] & 0xFF);
        return dstPort == DNS_PORT;
    }

    private String extractDomain(byte[] pkt, int len) {
        try {
            int ipHeaderLen = (pkt[0] & 0x0F) * 4;
            int qnameOffset = ipHeaderLen + 8 + 12; // UDP header (8) + DNS header (12)
            StringBuilder domain = new StringBuilder();
            while (qnameOffset < len) {
                int labelLen = pkt[qnameOffset] & 0xFF;
                if (labelLen == 0) break;
                if (domain.length() > 0) domain.append('.');
                domain.append(new String(pkt, qnameOffset + 1, labelLen));
                qnameOffset += labelLen + 1;
            }
            return domain.toString().toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] extractDnsPayload(byte[] pkt, int len) {
        int ipHeaderLen = (pkt[0] & 0x0F) * 4;
        int dnsStart = ipHeaderLen + 8;
        if (dnsStart >= len) return null;
        byte[] dns = new byte[len - dnsStart];
        System.arraycopy(pkt, dnsStart, dns, 0, dns.length);
        return dns;
    }

    private void sendNxDomain(FileOutputStream out, byte[] pkt, int len) throws IOException {
        byte[] dns = extractDnsPayload(pkt, len);
        if (dns == null || dns.length < 12) return;
        dns[2] = (byte) 0x81; // QR=1, RD=1
        dns[3] = (byte) 0x83; // RA=1, RCODE=3 (NXDOMAIN)
        out.write(wrapInIpUdp(dns, pkt, len));
    }

    private byte[] wrapInIpUdp(byte[] dnsPayload, byte[] origPkt, int origLen) {
        byte[] origDns = extractDnsPayload(origPkt, origLen);
        if (origDns == null) return dnsPayload;
        int ipHeaderLen = (origPkt[0] & 0x0F) * 4;
        byte[] reply = new byte[origLen - origDns.length + dnsPayload.length];
        System.arraycopy(origPkt, 0, reply, 0, ipHeaderLen + 8);
        // Swap src/dst IP and ports to form a valid reply
        System.arraycopy(origPkt, 12, reply, 16, 4);
        System.arraycopy(origPkt, 16, reply, 12, 4);
        reply[ipHeaderLen]     = origPkt[ipHeaderLen + 2];
        reply[ipHeaderLen + 1] = origPkt[ipHeaderLen + 3];
        reply[ipHeaderLen + 2] = origPkt[ipHeaderLen];
        reply[ipHeaderLen + 3] = origPkt[ipHeaderLen + 1];
        System.arraycopy(dnsPayload, 0, reply, ipHeaderLen + 8, dnsPayload.length);
        return reply;
    }
}
