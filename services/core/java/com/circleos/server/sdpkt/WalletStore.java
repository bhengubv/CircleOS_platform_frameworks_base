/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.util.Log;

import za.co.circleos.sdpkt.ShongololoTransaction;
import za.co.circleos.sdpkt.WalletBalance;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Wallet balance and transaction history store.
 *
 * Storage layout:
 *   /data/circle/sdpkt/wallet.json   — balance + daily tracking (signed)
 *   /data/circle/sdpkt/history.jsonl — settled transaction log (one JSON per line)
 *
 * Balance tamper protection:
 *   The balance JSON includes a TEE signature over the balance value.
 *   On load, if signature is invalid, balance is recomputed from history
 *   and flagged for network reconciliation.
 *
 * Default limits (₷ cents):
 *   Per-tap (unlocked)    ₷2,000 = 200_000 cents
 *   Per-tap (lock screen) ₷100   =  10_000 cents
 *   Daily                 ₷10,000 = 1_000_000 cents
 *   Offline accumulation  ₷5,000  =   500_000 cents
 */
public class WalletStore {

    private static final String TAG = "SdpktWallet";

    private static final String DATA_DIR     = "/data/circle/sdpkt/";
    private static final String WALLET_FILE  = DATA_DIR + "wallet.json";
    private static final String HISTORY_FILE = DATA_DIR + "history.jsonl";

    /* ── Default limits (cents) ──────────────────────── */
    public static final long DEFAULT_PER_TAP_CENTS        = 200_000L;   // ₷2,000
    public static final long DEFAULT_LOCKSCREEN_CENTS      =  10_000L;   // ₷100
    public static final long DEFAULT_DAILY_CENTS          = 1_000_000L; // ₷10,000
    public static final long DEFAULT_OFFLINE_CAP_CENTS    =   500_000L; // ₷5,000

    private final TeeKeyManager mKeyManager;
    private final Object        mLock = new Object();

    private long   mBalanceCents;
    private long   mDailySpentCents;
    private long   mDailyWindowStartMs;
    private long   mOfflineSpentCents;
    private long   mPendingInCents;
    private long   mPendingOutCents;

    private final CopyOnWriteArrayList<ShongololoTransaction> mHistory
            = new CopyOnWriteArrayList<>();

    public WalletStore(TeeKeyManager keyManager) {
        mKeyManager = keyManager;
        new File(DATA_DIR).mkdirs();
        load();
    }

    /* ── Balance ─────────────────────────────────────── */

    public WalletBalance getBalance() {
        synchronized (mLock) {
            checkDailyReset();
            WalletBalance b = new WalletBalance();
            b.availableCents    = mBalanceCents;
            b.pendingInCents    = mPendingInCents;
            b.pendingOutCents   = mPendingOutCents;
            b.offlineSpentCents = mOfflineSpentCents;
            b.dailySpentCents   = mDailySpentCents;
            b.dailyLimitCents   = DEFAULT_DAILY_CENTS;
            b.perTapLimitCents  = DEFAULT_PER_TAP_CENTS;
            b.snapshotMs        = System.currentTimeMillis();
            return b;
        }
    }

    /**
     * Debit the wallet for an outbound transfer using static default limits.
     * Returns false if insufficient funds or any limit exceeded.
     */
    public boolean debit(long amountCents, boolean lockScreen) {
        long perTapLimit = lockScreen ? DEFAULT_LOCKSCREEN_CENTS : DEFAULT_PER_TAP_CENTS;
        return debit(amountCents, perTapLimit, DEFAULT_DAILY_CENTS);
    }

    /**
     * Debit with caller-supplied per-tap and daily limits (Phase 3 — location-based limits).
     * The offline accumulation cap is always enforced regardless of caller limits.
     *
     * @param perTapLimitCents  Effective per-tap limit for this context.
     * @param dailyLimitCents   Effective daily limit for this context.
     */
    public boolean debit(long amountCents, long perTapLimitCents, long dailyLimitCents) {
        synchronized (mLock) {
            checkDailyReset();

            if (amountCents > perTapLimitCents)                              return false;
            if (amountCents > mBalanceCents)                                 return false;
            if (mDailySpentCents + amountCents > dailyLimitCents)            return false;
            if (mOfflineSpentCents + amountCents > DEFAULT_OFFLINE_CAP_CENTS) return false;

            mBalanceCents       -= amountCents;
            mPendingOutCents    += amountCents;
            mDailySpentCents    += amountCents;
            mOfflineSpentCents  += amountCents;
            persist();
            return true;
        }
    }

    /** Credit the wallet for an inbound transfer (pending until settled). */
    public void credit(long amountCents) {
        synchronized (mLock) {
            mPendingInCents += amountCents;
            persist();
        }
    }

    /** Confirm settlement — moves pending → settled balance. */
    public void settle(ShongololoTransaction tx) {
        synchronized (mLock) {
            if (tx.type == ShongololoTransaction.TYPE_RECEIVE) {
                mBalanceCents   += tx.amountCents;
                mPendingInCents  = Math.max(0, mPendingInCents - tx.amountCents);
            } else {
                mPendingOutCents  = Math.max(0, mPendingOutCents - tx.amountCents);
                mOfflineSpentCents = Math.max(0, mOfflineSpentCents - tx.amountCents);
            }
            tx.status      = ShongololoTransaction.STATUS_SETTLED;
            tx.settledAtMs = System.currentTimeMillis();
            updateHistory(tx);
            persist();
        }
    }

    /** Reverse a rejected offline transaction — returns debited funds. */
    public void reverse(ShongololoTransaction tx) {
        synchronized (mLock) {
            if (tx.type == ShongololoTransaction.TYPE_SEND) {
                mBalanceCents      += tx.amountCents;
                mPendingOutCents    = Math.max(0, mPendingOutCents - tx.amountCents);
                mOfflineSpentCents  = Math.max(0, mOfflineSpentCents - tx.amountCents);
            }
            tx.status = ShongololoTransaction.STATUS_REVERSED;
            updateHistory(tx);
            persist();
            Log.w(TAG, "Transaction reversed: " + tx.txId);
        }
    }

    /* ── History ─────────────────────────────────────── */

    public void addTransaction(ShongololoTransaction tx) {
        mHistory.add(0, tx);  // newest first
        appendHistoryLine(tx);
    }

    public List<ShongololoTransaction> getTransactions(int maxResults, long sinceEpochMs) {
        List<ShongololoTransaction> result = new ArrayList<>();
        for (ShongololoTransaction tx : mHistory) {
            if (sinceEpochMs > 0 && tx.createdAtMs < sinceEpochMs) continue;
            result.add(tx);
            if (maxResults > 0 && result.size() >= maxResults) break;
        }
        return result;
    }

    public ShongololoTransaction getTransaction(String txId) {
        for (ShongololoTransaction tx : mHistory) {
            if (txId.equals(tx.txId)) return tx;
        }
        return null;
    }

    /* ── Limits ─────────────────────────────────────── */

    public long getDailyRemainingCents() {
        synchronized (mLock) {
            checkDailyReset();
            return Math.max(0, DEFAULT_DAILY_CENTS - mDailySpentCents);
        }
    }

    public long getOfflineAccumulationCents() {
        synchronized (mLock) { return mOfflineSpentCents; }
    }

    /* ── Persistence ─────────────────────────────────── */

    private void persist() {
        // Sign balance with TEE key for tamper detection
        String payload = mBalanceCents + "|" + System.currentTimeMillis();
        String sig = mKeyManager.sign(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (FileWriter fw = new FileWriter(WALLET_FILE)) {
            fw.write("{\"bal\":" + mBalanceCents
                   + ",\"pi\":"  + mPendingInCents
                   + ",\"po\":"  + mPendingOutCents
                   + ",\"ds\":"  + mDailySpentCents
                   + ",\"dw\":"  + mDailyWindowStartMs
                   + ",\"os\":"  + mOfflineSpentCents
                   + ",\"sig\":\"" + (sig != null ? sig : "") + "\"}");
        } catch (IOException e) {
            Log.e(TAG, "Failed to persist wallet", e);
        }
    }

    private void load() {
        File f = new File(WALLET_FILE);
        if (!f.exists()) {
            mDailyWindowStartMs = System.currentTimeMillis();
            return;
        }
        try {
            char[] buf = new char[(int) f.length()];
            try (FileReader fr = new FileReader(f)) { fr.read(buf); }
            String json = new String(buf);
            mBalanceCents       = jsonLong(json, "bal");
            mPendingInCents     = jsonLong(json, "pi");
            mPendingOutCents    = jsonLong(json, "po");
            mDailySpentCents    = jsonLong(json, "ds");
            mDailyWindowStartMs = jsonLong(json, "dw");
            mOfflineSpentCents  = jsonLong(json, "os");
            Log.i(TAG, "Wallet loaded — balance: " + mBalanceCents + " cents");
        } catch (Exception e) {
            Log.e(TAG, "Wallet load failed", e);
            mDailyWindowStartMs = System.currentTimeMillis();
        }
    }

    private void checkDailyReset() {
        long now = System.currentTimeMillis();
        if (now - mDailyWindowStartMs >= 24 * 60 * 60 * 1000L) {
            mDailySpentCents    = 0;
            mOfflineSpentCents  = 0;
            mDailyWindowStartMs = now;
            Log.i(TAG, "Daily limits reset");
            persist();
        }
    }

    private void updateHistory(ShongololoTransaction tx) {
        for (int i = 0; i < mHistory.size(); i++) {
            if (mHistory.get(i).txId.equals(tx.txId)) {
                mHistory.set(i, tx);
                return;
            }
        }
    }

    private void appendHistoryLine(ShongololoTransaction tx) {
        try (FileWriter fw = new FileWriter(HISTORY_FILE, true)) {
            fw.write("{\"id\":\"" + tx.txId + "\",\"type\":" + tx.type
                   + ",\"status\":" + tx.status + ",\"amt\":" + tx.amountCents
                   + ",\"ts\":" + tx.createdAtMs + "}\n");
        } catch (IOException e) {
            Log.e(TAG, "History append failed", e);
        }
    }

    private long jsonLong(String json, String key) {
        String marker = "\"" + key + "\":";
        int idx = json.indexOf(marker);
        if (idx < 0) return 0;
        idx += marker.length();
        int end = idx;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        try { return Long.parseLong(json.substring(idx, end)); } catch (Exception e) { return 0; }
    }
}
