/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.os.Parcel;
import android.util.Log;

import za.co.circleos.sdpkt.ShongololoTransaction;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Settlement queue for outbound SDPKT transactions.
 *
 * Outbound transactions follow this lifecycle:
 *   NFC CONFIRM received → enqueue(tx)
 *   SyncManager online  → processAll() drains the queue
 *   Settlement OK        → WalletStore.settle(tx) + OfflineTransactionLog.markSettled()
 *   Settlement REJECTED  → WalletStore.reverse(tx) + OfflineTransactionLog.markReversed()
 *
 * Phase 2 settlement: no remote server yet. Outbound SEND transactions are
 * locally auto-settled after signature re-verification. Phase 4 will replace
 * the settle() method with an HTTP call to the settlement backend.
 *
 * Retry policy:
 *   Up to MAX_RETRIES attempts per transaction, with RETRY_DELAY_MS backoff.
 *   After MAX_RETRIES, the transaction is reversed to protect the sender.
 */
public class SettlementQueue {

    private static final String TAG             = "SdpktSettlement";
    private static final int    MAX_RETRIES     = 3;
    private static final long   RETRY_DELAY_MS  = 30_000L;  // 30 s

    /** CircleOS settlement backend endpoint. */
    private static final String SETTLEMENT_URL  =
            "https://sleptonapi.thegeeknetwork.co.za/api/sdpkt/settle";
    private static final int    SETTLE_TIMEOUT_MS = 15_000;

    // Mesh TX frame types — mirrors MeshProtocol constants to avoid cross-package import.
    private static final int MESH_TYPE_TX_SYNC = 0x20;
    private static final int MESH_TYPE_TX_ACK  = 0x21;

    private final OfflineTransactionLog mLog;
    private final WalletStore           mStore;
    private final TransactionSigner     mSigner;
    private final NonceCache            mNonceCache;

    /**
     * Callback invoked when settlement completes, so SyncManager can update state.
     */
    public interface SettlementListener {
        void onSettled(ShongololoTransaction tx);
        void onReversed(ShongololoTransaction tx, String reason);
    }

    private SettlementListener mListener;

    public SettlementQueue(OfflineTransactionLog log,
                           WalletStore store,
                           TransactionSigner signer,
                           NonceCache nonceCache) {
        mLog        = log;
        mStore      = store;
        mSigner     = signer;
        mNonceCache = nonceCache;
    }

    public void setListener(SettlementListener listener) {
        mListener = listener;
    }

    /** Add a new transaction to the pending settlement queue. */
    public void enqueue(ShongololoTransaction tx) {
        mLog.append(tx);
        Log.i(TAG, "Enqueued for settlement: " + tx.txId
                + " (" + tx.amountCents + " cents, type=" + tx.type + ")");
    }

    /** Current number of pending transactions. */
    public int getPendingCount() {
        return mLog.getPendingCount();
    }

    /**
     * Process all pending transactions. Called by SyncManager when network is available.
     * Runs synchronously — call from a worker thread.
     *
     * @return number of transactions settled successfully.
     */
    public int processAll() {
        List<ShongololoTransaction> pending = mLog.getPending();
        if (pending.isEmpty()) {
            Log.d(TAG, "Settlement queue empty");
            return 0;
        }

        Log.i(TAG, "Processing " + pending.size() + " pending transaction(s)");
        int settled = 0;

        for (ShongololoTransaction tx : pending) {
            boolean ok = settle(tx);
            if (ok) settled++;
        }

        Log.i(TAG, "Settlement complete: " + settled + "/" + pending.size() + " succeeded");
        return settled;
    }

    /**
     * Attempt to settle a single transaction.
     * Phase 2: local re-verification only (no network).
     *
     * @return true if settled, false if reversed.
     */
    private boolean settle(ShongololoTransaction tx) {
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                boolean ok = attemptSettle(tx);
                if (ok) {
                    mStore.settle(tx);
                    mLog.markSettled(tx.txId);
                    Log.i(TAG, "Settled: " + tx.txId);
                    if (mListener != null) mListener.onSettled(tx);
                    return true;
                }
                // Permanent rejection — no point retrying
                break;
            } catch (Exception e) {
                Log.w(TAG, "Settlement attempt " + attempt + " failed for " + tx.txId, e);
                if (attempt < MAX_RETRIES) {
                    try { Thread.sleep(RETRY_DELAY_MS); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }

        // All retries exhausted or permanent rejection → reverse
        mStore.reverse(tx);
        mLog.markReversed(tx.txId);
        Log.w(TAG, "Reversed after failed settlement: " + tx.txId);
        if (mListener != null) mListener.onReversed(tx, "Settlement failed after " + MAX_RETRIES + " attempts");
        return false;
    }

    /**
     * Core settlement logic.
     *
     * Step 1: local signature re-verification (catches TEE corruption / log tampering).
     * Step 2: HTTP POST to the CircleOS settlement backend.
     *
     * Return values:
     *   true  — settled successfully
     *   false — permanent rejection (do NOT retry; caller will reverse the tx)
     *   throw — transient failure (caller retries up to MAX_RETRIES times)
     */
    private boolean attemptSettle(ShongololoTransaction tx) {
        // ── Step 1: local re-verification ─────────────────────────────────────
        if (tx.type == ShongololoTransaction.TYPE_SEND) {
            int result = mSigner.verify(tx, mNonceCache);
            if (result != TransactionSigner.VERIFY_OK
                    && result != TransactionSigner.VERIFY_REPLAY) {
                Log.w(TAG, "Outbound tx " + tx.txId + " failed re-verification: " + result);
                return false; // permanent rejection — no point posting to server
            }
        }

        // ── Step 2: HTTP POST to settlement backend ────────────────────────────
        try {
            byte[] body = buildSettleJson(tx).getBytes(StandardCharsets.UTF_8);

            URL url = new URL(SETTLEMENT_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CircleOS-Version", "1");
            conn.setConnectTimeout(SETTLE_TIMEOUT_MS);
            conn.setReadTimeout(SETTLE_TIMEOUT_MS);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }

            int code = conn.getResponseCode();
            conn.disconnect();

            if (code >= 200 && code < 300) {
                Log.i(TAG, "Settlement OK: " + tx.txId + " HTTP " + code);
                return true;
            } else if (code == 409) {
                // Conflict — duplicate / already settled; treat as success.
                Log.i(TAG, "Settlement duplicate (409): " + tx.txId);
                return true;
            } else if (code >= 400 && code < 500) {
                // Client error: double-spend, invalid signature, etc. — permanent.
                Log.w(TAG, "Settlement permanently rejected: " + tx.txId + " HTTP " + code);
                return false;
            } else {
                // 5xx or unexpected — throw so the retry loop retries.
                throw new RuntimeException("Settlement server error HTTP " + code
                        + " for " + tx.txId);
            }
        } catch (IOException e) {
            throw new RuntimeException("Settlement HTTP failed for " + tx.txId, e);
        }
    }

    /** Serialises a transaction to JSON for the settlement POST body. */
    private String buildSettleJson(ShongololoTransaction tx) {
        JSONObject o = new JSONObject();
        try {
            o.put("tx_id",            tx.txId);
            o.put("amount_cents",     tx.amountCents);
            o.put("type",             tx.type);
            o.put("sender_device_id", tx.senderDeviceId);
            o.put("timestamp_ms",     System.currentTimeMillis());
        } catch (JSONException e) {
            Log.w(TAG, "buildSettleJson: JSON error for " + tx.txId, e);
        }
        return o.toString();
    }

    /**
     * Called by SdpktTitaniumService when a TYPE_TX_SYNC or TYPE_TX_ACK mesh frame arrives.
     *
     * TYPE_TX_SYNC (0x20): a peer is sending us a transaction over the mesh — deserialise
     *   from Parcel and enqueue for settlement.
     * TYPE_TX_ACK  (0x21): our previously submitted transaction was acknowledged by a peer —
     *   informational only; settlement still happens via the HTTP backend.
     */
    public void onMeshFrame(String senderDeviceId, byte[] payload, int frameType) {
        if (frameType == MESH_TYPE_TX_SYNC) {
            Parcel p = Parcel.obtain();
            try {
                p.unmarshall(payload, 0, payload.length);
                p.setDataPosition(0);
                ShongololoTransaction tx =
                        ShongololoTransaction.CREATOR.createFromParcel(p);
                if (tx != null && tx.txId != null && !tx.txId.isEmpty()) {
                    Log.i(TAG, "onMeshFrame: TX_SYNC from " + senderDeviceId
                            + " txId=" + tx.txId + " amount=" + tx.amountCents);
                    enqueue(tx);
                } else {
                    Log.w(TAG, "onMeshFrame: TX_SYNC from " + senderDeviceId
                            + " — null or empty txId after deserialisation");
                }
            } catch (Exception e) {
                Log.w(TAG, "onMeshFrame: TX_SYNC deserialise failed from " + senderDeviceId, e);
            } finally {
                p.recycle();
            }
        } else if (frameType == MESH_TYPE_TX_ACK) {
            Log.d(TAG, "onMeshFrame: TX_ACK from " + senderDeviceId
                    + " — settlement via HTTP backend");
        } else {
            Log.d(TAG, "onMeshFrame: unknown frameType=0x"
                    + Integer.toHexString(frameType) + " from " + senderDeviceId);
        }
    }

    /**
     * Re-load pending transactions from disk and re-enqueue any that were in-flight
     * when the process restarted. Called from SdpktTitaniumService.onBootPhase().
     */
    public void restoreFromLog() {
        int count = mLog.getPendingCount();
        if (count > 0) {
            Log.i(TAG, "Restored " + count + " pending transaction(s) from offline log");
        }
        // Prune old settled/reversed entries
        mLog.prune();
    }
}
