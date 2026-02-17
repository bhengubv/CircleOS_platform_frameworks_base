/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.util.Base64;
import android.util.Log;

import za.co.circleos.sdpkt.ShongololoTransaction;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Transaction signing and offline verification.
 *
 * Signing payload (canonical form for ECDSA):
 *   "{txId}|{timestamp}|{nonce}|{senderPubkey}|{receiverPubkey}|{amountCents}|{currency}"
 *   UTF-8 encoded, signed with SHA256withECDSA via TeeKeyManager.
 *
 * Replay protection:
 *   Each transaction has a unique UUID (txId) and a 32-byte random nonce.
 *   Receivers cache recent nonces for 24 hours to detect replays.
 *
 * Timestamp drift allowance:
 *   ±5 minutes from receiver's clock (accommodates devices with slightly different time).
 */
public class TransactionSigner {

    private static final String TAG = "SdpktSigner";

    /** Max timestamp drift accepted during offline verification (5 minutes). */
    private static final long MAX_DRIFT_MS = 5 * 60 * 1000L;

    private final TeeKeyManager mKeyManager;

    public TransactionSigner(TeeKeyManager keyManager) {
        mKeyManager = keyManager;
    }

    /**
     * Build and sign a new outbound transaction.
     * Returns null if signing fails (TEE unavailable).
     */
    public ShongololoTransaction buildAndSign(
            long amountCents, String receiverPubkeyB64, String memo) {

        ShongololoTransaction tx = new ShongololoTransaction();
        tx.txId           = UUID.randomUUID().toString();
        tx.type           = ShongololoTransaction.TYPE_SEND;
        tx.status         = ShongololoTransaction.STATUS_PENDING_SETTLEMENT;
        tx.amountCents    = amountCents;
        tx.currency       = "SHG";
        tx.senderPubkey   = mKeyManager.getEncodedPublicKey();
        tx.receiverPubkey = receiverPubkeyB64;
        tx.nonce          = generateNonce();
        tx.memo           = memo;
        tx.createdAtMs    = System.currentTimeMillis();

        // Derive sender device ID
        try {
            byte[] senderBytes = Base64.decode(tx.senderPubkey, Base64.NO_WRAP);
            tx.senderDeviceId = TeeKeyManager.sha256Hex(senderBytes);
        } catch (Exception e) {
            tx.senderDeviceId = "unknown";
        }

        // Sign the canonical payload
        byte[] payload = canonicalPayload(tx);
        tx.signature = mKeyManager.sign(payload);

        if (tx.signature == null) {
            Log.e(TAG, "Signing failed — TEE unavailable?");
            return null;
        }

        Log.d(TAG, "Signed tx " + tx.txId + " for " + tx.amountCents + " cents");
        return tx;
    }

    /**
     * Verify an inbound transaction offline.
     * @return VERIFY_OK, VERIFY_BAD_SIGNATURE, VERIFY_REPLAY, or VERIFY_CLOCK_DRIFT
     */
    public int verify(ShongololoTransaction tx, NonceCache nonceCache) {
        // 1. Timestamp drift
        long drift = Math.abs(System.currentTimeMillis() - tx.createdAtMs);
        if (drift > MAX_DRIFT_MS) {
            Log.w(TAG, "tx " + tx.txId + " clock drift " + drift + "ms — rejected");
            return VERIFY_CLOCK_DRIFT;
        }

        // 2. Nonce uniqueness
        if (nonceCache.contains(tx.nonce)) {
            Log.w(TAG, "tx " + tx.txId + " replay — nonce already seen");
            return VERIFY_REPLAY;
        }

        // 3. Signature
        byte[] payload = canonicalPayload(tx);
        boolean sigOk = mKeyManager.verify(payload, tx.signature, tx.senderPubkey);
        if (!sigOk) {
            Log.w(TAG, "tx " + tx.txId + " invalid signature");
            return VERIFY_BAD_SIGNATURE;
        }

        nonceCache.add(tx.nonce, tx.createdAtMs);
        Log.d(TAG, "tx " + tx.txId + " verified OK");
        return VERIFY_OK;
    }

    /* ── Verification result codes ─────────────────── */
    public static final int VERIFY_OK            = 0;
    public static final int VERIFY_BAD_SIGNATURE = 1;
    public static final int VERIFY_REPLAY        = 2;
    public static final int VERIFY_CLOCK_DRIFT   = 3;

    /* ── Helpers ─────────────────────────────────────── */

    /**
     * Canonical signing payload — deterministic string representation.
     * Format: "{txId}|{createdAtMs}|{nonce}|{senderPubkey}|{receiverPubkey}|{amountCents}|{currency}"
     */
    static byte[] canonicalPayload(ShongololoTransaction tx) {
        String s = tx.txId + "|"
                + tx.createdAtMs + "|"
                + tx.nonce + "|"
                + tx.senderPubkey + "|"
                + tx.receiverPubkey + "|"
                + tx.amountCents + "|"
                + tx.currency;
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private String generateNonce() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }
}
