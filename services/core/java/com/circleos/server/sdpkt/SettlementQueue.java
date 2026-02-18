/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.os.Handler;
import android.util.Log;

import za.co.circleos.sdpkt.ShongololoTransaction;

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

    private static final String TAG           = "SdpktSettlement";
    private static final int    MAX_RETRIES   = 3;
    private static final long   RETRY_DELAY_MS= 30_000L;  // 30 s

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
     * Phase 2 (local verification):
     *   - For SEND: re-verify our own signature — it must be valid.
     *     This catches TEE corruption or log tampering.
     *   - For RECEIVE: already verified on receipt; just confirm funds.
     *
     * Phase 4 (network settlement):
     *   Replace this method body with an HTTP POST to the Circle settlement endpoint.
     */
    private boolean attemptSettle(ShongololoTransaction tx) {
        if (tx.type == ShongololoTransaction.TYPE_SEND) {
            // Re-verify our own outbound signature to detect log tampering
            int result = mSigner.verify(tx, mNonceCache);
            if (result != TransactionSigner.VERIFY_OK
                    && result != TransactionSigner.VERIFY_REPLAY) {
                // VERIFY_REPLAY is acceptable for re-settlement — nonce was already consumed
                Log.w(TAG, "Outbound tx " + tx.txId + " failed re-verification: " + result);
                return false;
            }
        }
        // All good — Phase 2 local settlement succeeds
        return true;
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
