/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Replay protection nonce cache.
 *
 * Stores seen nonces for 24 hours. Nonces older than the TTL are evicted
 * on each add() call (lazy eviction — no background thread needed).
 *
 * Max capacity: 10,000 entries (enough for very high-frequency use).
 */
public class NonceCache {

    private static final long TTL_MS   = 24 * 60 * 60 * 1000L;
    private static final int  MAX_SIZE = 10_000;

    // nonce → timestamp of the transaction that used it
    private final LinkedHashMap<String, Long> mCache =
            new LinkedHashMap<String, Long>(256, 0.75f, false) {
                @Override protected boolean removeEldestEntry(Map.Entry eldest) {
                    return size() > MAX_SIZE;
                }
            };

    public synchronized boolean contains(String nonce) {
        return mCache.containsKey(nonce);
    }

    public synchronized void add(String nonce, long txTimestampMs) {
        evictExpired();
        mCache.put(nonce, txTimestampMs);
    }

    private void evictExpired() {
        long cutoff = System.currentTimeMillis() - TTL_MS;
        Iterator<Map.Entry<String, Long>> it = mCache.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue() < cutoff) it.remove();
            else break; // LinkedHashMap preserves insertion order
        }
    }

    public synchronized int size() {
        return mCache.size();
    }
}
