/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

package com.circleos.server.mesh;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Multi-hop routing for the mesh — turns the single-hop direct link into a true
 * store-and-forward relay mesh so a message reaches a peer that isn't in direct
 * range, by hopping through intermediate Circle devices.
 *
 * Frame v3 header (then payload), the whole thing then link-encrypted by
 * {@link MeshLinkPrivacy} so only Circle devices — not outside observers — can
 * read even the routing header:
 *
 *   [ver=3][ttl][hop][flags][msgId:8][dst:8][src:8][len:4 BE][payload]
 *
 * Privacy note: relaying inherently means a Circle relay must see the destination
 * to forward it (that's true of any routed mesh). Outsiders see nothing (link
 * encryption) and content stays E2E end-to-end; the cost is that a Circle relay
 * learns "dst is somewhere past me". Pure Java — unit-testable off-device.
 */
final class MeshRouter {

    static final int VERSION = 3;
    static final int DEFAULT_TTL = 5;
    static final int HEADER = 1 + 1 + 1 + 1 + 8 + 8 + 8 + 4; // 32
    static final int FLAG_BROADCAST = 0x01;

    enum Decision { DELIVER, RELAY, DROP }

    static final class Parsed {
        int ver, ttl, hop, flags, len;
        byte[] msgId, dst, src, payload;
    }

    private final int mMaxSeen;
    private final Map<String, Boolean> mSeen;

    MeshRouter(int dedupCacheSize) {
        mMaxSeen = dedupCacheSize;
        mSeen = new LinkedHashMap<String, Boolean>(16, 0.75f, true) {
            @Override protected boolean removeEldestEntry(Map.Entry<String, Boolean> e) {
                return size() > mMaxSeen;
            }
        };
    }

    /** Build a v3 frame to {@code dst8} from {@code src8}. dst8 == null -> broadcast. */
    byte[] encode(byte[] dst8, byte[] src8, int ttl, byte[] payload) {
        byte[] msgId = new byte[8];
        new SecureRandom().nextBytes(msgId);
        return assemble(ttl, 0, dst8 == null ? FLAG_BROADCAST : 0, msgId,
                dst8 == null ? new byte[8] : dst8, src8, payload);
    }

    Parsed decode(byte[] frame) {
        if (frame == null || frame.length < HEADER) return null;
        Parsed p = new Parsed();
        p.ver = frame[0] & 0xff;
        if (p.ver != VERSION) return null;
        p.ttl = frame[1] & 0xff;
        p.hop = frame[2] & 0xff;
        p.flags = frame[3] & 0xff;
        p.msgId = Arrays.copyOfRange(frame, 4, 12);
        p.dst = Arrays.copyOfRange(frame, 12, 20);
        p.src = Arrays.copyOfRange(frame, 20, 28);
        p.len = ((frame[28] & 0xff) << 24) | ((frame[29] & 0xff) << 16)
                | ((frame[30] & 0xff) << 8) | (frame[31] & 0xff);
        if (p.len < 0 || HEADER + p.len > frame.length) return null;
        p.payload = Arrays.copyOfRange(frame, HEADER, HEADER + p.len);
        return p;
    }

    /** Decide what to do with a freshly-decoded frame for the local node {@code myId8}. */
    Decision route(Parsed p, byte[] myId8) {
        if (p == null) return Decision.DROP;
        String key = hex(p.msgId);
        if (mSeen.containsKey(key)) return Decision.DROP; // already handled (loop / duplicate)
        mSeen.put(key, Boolean.TRUE);
        boolean forMe = (p.flags & FLAG_BROADCAST) != 0 || Arrays.equals(p.dst, myId8);
        if (forMe) return Decision.DELIVER;
        if (p.hop + 1 >= p.ttl) return Decision.DROP; // TTL exhausted
        return Decision.RELAY;
    }

    /** Re-encode a frame for forwarding: same everything, hop incremented. */
    byte[] reframeForRelay(Parsed p) {
        return assemble(p.ttl, p.hop + 1, p.flags, p.msgId, p.dst, p.src, p.payload);
    }

    /** True if we've recently seen a broadcast we both delivered AND should still relay. */
    boolean alreadySeen(byte[] msgId) {
        return mSeen.containsKey(hex(msgId));
    }

    // ── internals ──

    private static byte[] assemble(int ttl, int hop, int flags, byte[] msgId,
                                   byte[] dst, byte[] src, byte[] payload) {
        byte[] out = new byte[HEADER + payload.length];
        out[0] = (byte) VERSION;
        out[1] = (byte) (ttl & 0xff);
        out[2] = (byte) (hop & 0xff);
        out[3] = (byte) (flags & 0xff);
        System.arraycopy(msgId, 0, out, 4, 8);
        System.arraycopy(pad8(dst), 0, out, 12, 8);
        System.arraycopy(pad8(src), 0, out, 20, 8);
        out[28] = (byte) ((payload.length >> 24) & 0xff);
        out[29] = (byte) ((payload.length >> 16) & 0xff);
        out[30] = (byte) ((payload.length >> 8) & 0xff);
        out[31] = (byte) (payload.length & 0xff);
        System.arraycopy(payload, 0, out, HEADER, payload.length);
        return out;
    }

    private static byte[] pad8(byte[] b) {
        if (b != null && b.length == 8) return b;
        byte[] o = new byte[8];
        if (b != null) System.arraycopy(b, 0, o, 0, Math.min(8, b.length));
        return o;
    }

    /** 16-hex-char short id -> 8 bytes. */
    static byte[] idToBytes(String shortHexId) {
        byte[] o = new byte[8];
        if (shortHexId == null) return o;
        try {
            for (int i = 0; i < 8 && (i * 2 + 1) < shortHexId.length(); i++) {
                o[i] = (byte) Integer.parseInt(shortHexId.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (Throwable ignored) {
        }
        return o;
    }

    /** 8 bytes -> 16-hex-char short id. */
    static String bytesToId(byte[] b) {
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < 8 && i < (b == null ? 0 : b.length); i++) {
            sb.append(String.format(Locale.US, "%02x", b[i] & 0xff));
        }
        return sb.toString();
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format(Locale.US, "%02x", x & 0xff));
        return sb.toString();
    }
}
