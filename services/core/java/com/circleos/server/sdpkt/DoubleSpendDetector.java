/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.util.Log;

import za.co.circleos.sdpkt.ShongololoTransaction;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Double-spend and replay detection for incoming NFC transactions.
 *
 * Checks (in order):
 *  1. Nonce uniqueness    — via NonceCache (24h TTL, already in Phase 1)
 *  2. Transaction ID      — unique UUID, not previously seen in log
 *  3. Clock drift         — timestamp within ±5 min (TransactionSigner)
 *  4. Peer rate limit     — max MAX_TX_PER_HOUR transactions per peer per hour
 *  5. Blacklist           — peers who sent MAX_BAD_ATTEMPTS bad transactions
 *
 * The detector is stateless across reboots except for the blacklist, which
 * is intentionally volatile (devices clear the slate on reboot to avoid
 * permanent denial-of-service from a false positive).
 */
public class DoubleSpendDetector {

    private static final String TAG = "SdpktDSD";

    /* ── Tuning constants ──────────────────────────────────── */

    /** Max transactions accepted from a single peer per hour. */
    private static final int  MAX_TX_PER_HOUR    = 20;
    /** After this many bad-signature attempts, the peer is blacklisted. */
    private static final int  MAX_BAD_ATTEMPTS   = 5;
    /** How long a rate-limit window lasts (ms). */
    private static final long RATE_WINDOW_MS     = 60 * 60 * 1000L; // 1 hour

    /* ── Result codes ──────────────────────────────────────── */
    public static final int OK                   = 0;
    public static final int ERR_DUPLICATE_TX     = 1;  // same txId seen before
    public static final int ERR_DUPLICATE_NONCE  = 2;  // nonce already in cache
    public static final int ERR_RATE_LIMITED     = 3;  // peer sending too fast
    public static final int ERR_BLACKLISTED      = 4;  // peer is blacklisted
    public static final int ERR_CLOCK_DRIFT      = 5;  // timestamp out of range
    public static final int ERR_BAD_SIGNATURE    = 6;  // signature failed

    /* ── State ─────────────────────────────────────────────── */

    private final NonceCache              mNonceCache;
    private final OfflineTransactionLog   mPendingLog;
    private final TransactionSigner       mSigner;

    /** peer device ID → count of transactions in current window */
    private final HashMap<String, RateWindow> mRateWindows = new HashMap<>();

    /** peer device ID → bad-attempt counter */
    private final HashMap<String, Integer> mBadAttempts = new HashMap<>();

    /** Set of blacklisted peer device IDs (volatile — resets on reboot). */
    private final java.util.HashSet<String> mBlacklist = new java.util.HashSet<>();

    public DoubleSpendDetector(NonceCache nonceCache,
                               OfflineTransactionLog pendingLog,
                               TransactionSigner signer) {
        mNonceCache = nonceCache;
        mPendingLog = pendingLog;
        mSigner     = signer;
    }

    /**
     * Full validation of an incoming transaction before it is accepted.
     *
     * @return OK (0) or an ERR_* constant.
     */
    public int check(ShongololoTransaction tx) {
        if (tx == null) return ERR_BAD_SIGNATURE;

        String peer = tx.senderDeviceId != null ? tx.senderDeviceId : "?";

        // 1. Blacklist check — fast path
        synchronized (mBlacklist) {
            if (mBlacklist.contains(peer)) {
                Log.w(TAG, "Rejecting tx from blacklisted peer: " + peer);
                return ERR_BLACKLISTED;
            }
        }

        // 2. Clock drift
        long driftMs = Math.abs(System.currentTimeMillis() - tx.createdAtMs);
        if (driftMs > TransactionSigner.MAX_DRIFT_MS) {
            Log.w(TAG, "Clock drift too large: " + driftMs + " ms, peer=" + peer);
            recordBadAttempt(peer);
            return ERR_CLOCK_DRIFT;
        }

        // 3. Nonce uniqueness (also checks again in TransactionSigner.verify — belt+braces)
        if (tx.nonce != null && mNonceCache.contains(tx.nonce)) {
            Log.w(TAG, "Duplicate nonce from peer=" + peer);
            recordBadAttempt(peer);
            return ERR_DUPLICATE_NONCE;
        }

        // 4. Transaction ID uniqueness against pending log + nonce cache lookup
        if (mPendingLog.contains(tx.txId)) {
            Log.w(TAG, "Duplicate txId from peer=" + peer + " id=" + tx.txId);
            recordBadAttempt(peer);
            return ERR_DUPLICATE_TX;
        }

        // 5. Signature verification (full ECDSA check)
        int verifyResult = mSigner.verify(tx, mNonceCache);
        if (verifyResult == TransactionSigner.VERIFY_REPLAY) {
            recordBadAttempt(peer);
            return ERR_DUPLICATE_NONCE;
        }
        if (verifyResult == TransactionSigner.VERIFY_CLOCK_DRIFT) {
            recordBadAttempt(peer);
            return ERR_CLOCK_DRIFT;
        }
        if (verifyResult != TransactionSigner.VERIFY_OK) {
            Log.w(TAG, "Signature verification failed (" + verifyResult + ") peer=" + peer);
            recordBadAttempt(peer);
            return ERR_BAD_SIGNATURE;
        }

        // 6. Per-peer rate limit (checked after signature to avoid DoS via fake peer IDs)
        if (!checkRate(peer)) {
            Log.w(TAG, "Rate limit exceeded for peer=" + peer);
            return ERR_RATE_LIMITED;
        }

        return OK;
    }

    /** Called by the NFC engine after a check() == OK to consume the nonce. */
    public void recordAccepted(ShongololoTransaction tx) {
        if (tx.nonce != null) {
            mNonceCache.add(tx.nonce, tx.createdAtMs);
        }
        incrementRate(tx.senderDeviceId != null ? tx.senderDeviceId : "?");
    }

    /** Expose a human-readable reason for logging/UI. */
    public static String describe(int code) {
        switch (code) {
            case OK:                  return "OK";
            case ERR_DUPLICATE_TX:    return "duplicate transaction ID";
            case ERR_DUPLICATE_NONCE: return "duplicate nonce (replay)";
            case ERR_RATE_LIMITED:    return "sender rate limit exceeded";
            case ERR_BLACKLISTED:     return "sender blacklisted";
            case ERR_CLOCK_DRIFT:     return "clock drift too large";
            case ERR_BAD_SIGNATURE:   return "invalid signature";
            default:                  return "unknown error " + code;
        }
    }

    /* ── Rate limiting ─────────────────────────────────────── */

    private synchronized boolean checkRate(String peer) {
        RateWindow w = mRateWindows.get(peer);
        long now = System.currentTimeMillis();
        if (w == null || now - w.windowStartMs >= RATE_WINDOW_MS) {
            mRateWindows.put(peer, new RateWindow(now, 0));
            return true;
        }
        return w.count < MAX_TX_PER_HOUR;
    }

    private synchronized void incrementRate(String peer) {
        long now = System.currentTimeMillis();
        RateWindow w = mRateWindows.get(peer);
        if (w == null || now - w.windowStartMs >= RATE_WINDOW_MS) {
            mRateWindows.put(peer, new RateWindow(now, 1));
        } else {
            w.count++;
        }
    }

    /* ── Bad-attempt tracking ──────────────────────────────── */

    private synchronized void recordBadAttempt(String peer) {
        int count = mBadAttempts.getOrDefault(peer, 0) + 1;
        mBadAttempts.put(peer, count);
        if (count >= MAX_BAD_ATTEMPTS) {
            synchronized (mBlacklist) {
                mBlacklist.add(peer);
            }
            Log.w(TAG, "Peer blacklisted after " + count + " bad attempts: " + peer);
        }
    }

    /* ── Inner types ───────────────────────────────────────── */

    private static final class RateWindow {
        long windowStartMs;
        int  count;
        RateWindow(long start, int c) { windowStartMs = start; count = c; }
    }
}
