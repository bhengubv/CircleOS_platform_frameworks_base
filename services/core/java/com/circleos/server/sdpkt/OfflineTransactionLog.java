/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.util.Log;

import za.co.circleos.sdpkt.ShongololoTransaction;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Persistent log of offline (pending-settlement) transactions.
 *
 * Storage: /data/circle/sdpkt/pending.jsonl
 *   One JSON record per line. Each line:
 *     {"id":"<uuid>","type":<int>,"amt":<long>,"ts":<long>,"status":<int>,
 *      "sender_pubkey":"<b64>","receiver_pubkey":"<b64>","nonce":"<b64>",
 *      "sig":"<b64>","currency":"SHG","memo":"<str>"}
 *
 * Lifecycle:
 *   - append(tx)       — add new PENDING_SETTLEMENT record
 *   - markSettled(id)  — update status to SETTLED; entry kept for audit
 *   - markReversed(id) — update status to REVERSED; entry kept for audit
 *   - getPending()     — return all PENDING_SETTLEMENT entries (to retry)
 *   - prune()          — remove SETTLED/REVERSED entries older than 30 days
 */
public class OfflineTransactionLog {

    private static final String TAG          = "SdpktOfflineLog";
    private static final String PENDING_FILE = "/data/circle/sdpkt/pending.jsonl";
    private static final long   PRUNE_AGE_MS = 30L * 24 * 60 * 60 * 1000; // 30 days

    private final Object mLock = new Object();

    /** In-memory mirror for fast access — rebuilt on load. */
    private final CopyOnWriteArrayList<ShongololoTransaction> mEntries
            = new CopyOnWriteArrayList<>();

    public OfflineTransactionLog() {
        new File("/data/circle/sdpkt/").mkdirs();
        load();
    }

    /* ── Write operations ────────────────────────────────── */

    /** Append a new transaction as PENDING_SETTLEMENT. */
    public void append(ShongololoTransaction tx) {
        synchronized (mLock) {
            tx.status = ShongololoTransaction.STATUS_PENDING_SETTLEMENT;
            mEntries.add(0, tx);  // newest-first
            rewrite();            // rewrite entire file (keeps it consistent)
        }
        Log.d(TAG, "Appended pending tx: " + tx.txId + " ₷" + tx.amountCents);
    }

    /** Update a transaction to SETTLED. */
    public boolean markSettled(String txId) {
        return updateStatus(txId, ShongololoTransaction.STATUS_SETTLED);
    }

    /** Update a transaction to REVERSED. */
    public boolean markReversed(String txId) {
        return updateStatus(txId, ShongololoTransaction.STATUS_REVERSED);
    }

    private boolean updateStatus(String txId, int newStatus) {
        synchronized (mLock) {
            for (int i = 0; i < mEntries.size(); i++) {
                ShongololoTransaction tx = mEntries.get(i);
                if (txId.equals(tx.txId)) {
                    tx.status = newStatus;
                    if (newStatus == ShongololoTransaction.STATUS_SETTLED) {
                        tx.settledAtMs = System.currentTimeMillis();
                    }
                    mEntries.set(i, tx);
                    rewrite();
                    return true;
                }
            }
        }
        Log.w(TAG, "updateStatus: tx not found: " + txId);
        return false;
    }

    /* ── Read operations ─────────────────────────────────── */

    /** All transactions with STATUS_PENDING_SETTLEMENT, oldest-first for fair processing. */
    public List<ShongololoTransaction> getPending() {
        List<ShongololoTransaction> result = new ArrayList<>();
        for (int i = mEntries.size() - 1; i >= 0; i--) {
            ShongololoTransaction tx = mEntries.get(i);
            if (tx.status == ShongololoTransaction.STATUS_PENDING_SETTLEMENT) {
                result.add(tx);
            }
        }
        return result;
    }

    /** All entries (any status), newest-first. */
    public List<ShongololoTransaction> getAll() {
        return new ArrayList<>(mEntries);
    }

    /** Total number of PENDING_SETTLEMENT entries. */
    public int getPendingCount() {
        int count = 0;
        for (ShongololoTransaction tx : mEntries) {
            if (tx.status == ShongololoTransaction.STATUS_PENDING_SETTLEMENT) count++;
        }
        return count;
    }

    /** True if a transaction ID already exists in the log (duplicate detection). */
    public boolean contains(String txId) {
        for (ShongololoTransaction tx : mEntries) {
            if (txId.equals(tx.txId)) return true;
        }
        return false;
    }

    /* ── Maintenance ─────────────────────────────────────── */

    /** Remove entries that are settled/reversed AND older than PRUNE_AGE_MS. */
    public void prune() {
        long cutoff = System.currentTimeMillis() - PRUNE_AGE_MS;
        synchronized (mLock) {
            boolean changed = mEntries.removeIf(tx ->
                    tx.status != ShongololoTransaction.STATUS_PENDING_SETTLEMENT
                    && tx.createdAtMs < cutoff);
            if (changed) {
                rewrite();
                Log.i(TAG, "Pruned settled/reversed entries older than 30 days");
            }
        }
    }

    /* ── Persistence ─────────────────────────────────────── */

    private void load() {
        File f = new File(PENDING_FILE);
        if (!f.exists()) return;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                ShongololoTransaction tx = fromJson(line);
                if (tx != null) mEntries.add(tx);
            }
            Log.i(TAG, "Loaded " + mEntries.size() + " pending-log entries");
        } catch (IOException e) {
            Log.e(TAG, "Failed to load pending log", e);
        }
    }

    /** Rewrite entire file from in-memory list (entries already newest-first). */
    private void rewrite() {
        try (FileWriter fw = new FileWriter(PENDING_FILE, false)) {
            // Write oldest-first so re-load preserves insertion order
            for (int i = mEntries.size() - 1; i >= 0; i--) {
                fw.write(toJson(mEntries.get(i)));
                fw.write('\n');
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to rewrite pending log", e);
        }
    }

    /* ── JSON helpers (no external dependency) ───────────── */

    private String toJson(ShongololoTransaction tx) {
        return "{\"id\":\"" + tx.txId + "\""
             + ",\"type\":"   + tx.type
             + ",\"status\":" + tx.status
             + ",\"amt\":"    + tx.amountCents
             + ",\"ts\":"     + tx.createdAtMs
             + ",\"settled\":" + tx.settledAtMs
             + ",\"sender\":\""   + esc(tx.senderPubkey)   + "\""
             + ",\"sender_did\":\"" + esc(tx.senderDeviceId) + "\""
             + ",\"receiver\":\"" + esc(tx.receiverPubkey)  + "\""
             + ",\"nonce\":\""   + esc(tx.nonce)           + "\""
             + ",\"sig\":\""     + esc(tx.signature)       + "\""
             + ",\"cur\":\""     + esc(tx.currency)        + "\""
             + ",\"memo\":\""    + esc(tx.memo)            + "\"}";
    }

    private ShongololoTransaction fromJson(String json) {
        try {
            ShongololoTransaction tx = new ShongololoTransaction();
            tx.txId           = str(json, "id");
            tx.type           = (int) lng(json, "type");
            tx.status         = (int) lng(json, "status");
            tx.amountCents    = lng(json, "amt");
            tx.createdAtMs    = lng(json, "ts");
            tx.settledAtMs    = lng(json, "settled");
            tx.senderPubkey   = str(json, "sender");
            tx.senderDeviceId = str(json, "sender_did");
            tx.receiverPubkey = str(json, "receiver");
            tx.nonce          = str(json, "nonce");
            tx.signature      = str(json, "sig");
            tx.currency       = str(json, "cur");
            tx.memo           = str(json, "memo");
            if (tx.txId == null || tx.txId.isEmpty()) return null;
            return tx;
        } catch (Exception e) {
            Log.w(TAG, "Malformed pending log entry: " + json);
            return null;
        }
    }

    private String str(String json, String key) {
        String marker = "\"" + key + "\":\"";
        int s = json.indexOf(marker);
        if (s < 0) return "";
        s += marker.length();
        int e = json.indexOf("\"", s);
        return e > s ? json.substring(s, e) : "";
    }

    private long lng(String json, String key) {
        String marker = "\"" + key + "\":";
        int idx = json.indexOf(marker);
        if (idx < 0) return 0;
        idx += marker.length();
        int end = idx;
        while (end < json.length()
               && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        try { return Long.parseLong(json.substring(idx, end)); } catch (Exception e) { return 0; }
    }

    private String esc(String s) { return s != null ? s.replace("\"", "\\\"") : ""; }
}
