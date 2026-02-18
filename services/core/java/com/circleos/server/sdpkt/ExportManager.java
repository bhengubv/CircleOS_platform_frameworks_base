/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import za.co.circleos.sdpkt.ShongololoTransaction;

/**
 * Exports the wallet transaction history to CSV or JSON files on external storage.
 *
 * Output directory: {@code /sdcard/Download/}
 * CSV filename: {@code shongololo_YYYYMMDD_HHmmss.csv}
 * JSON filename: {@code shongololo_YYYYMMDD_HHmmss.json}
 *
 * The caller is responsible for holding the WRITE_EXTERNAL_STORAGE permission
 * (or targeting API 29+ with MediaStore instead).
 */
public final class ExportManager {

    private static final String TAG = "Sdpkt.Export";

    private static final String CSV_HEADER =
            "date,type,amount_cents,amount,peer,memo,status,tx_id\n";

    private ExportManager() {}

    /** Export transactions as CSV. Returns the created File, or null on failure. */
    public static File exportCsv(List<ShongololoTransaction> txs, File downloadDir) {
        File out = new File(downloadDir, buildFilename("csv"));
        try (FileWriter w = new FileWriter(out, false)) {
            w.write(CSV_HEADER);
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
            for (ShongololoTransaction tx : txs) {
                String type   = tx.type == ShongololoTransaction.TYPE_SEND ? "SENT" : "RECEIVED";
                String date   = sdf.format(new Date(tx.createdAtMs));
                String peer   = tx.type == ShongololoTransaction.TYPE_SEND
                                ? safe(tx.receiverPubkey) : safe(tx.senderDeviceId);
                String memo   = safe(tx.memo);
                String status = statusName(tx.status);
                String txId   = safe(tx.txId);
                long   cents  = tx.amountCents;
                String amount = String.format(Locale.US, "\u20b7%,d.%02d", cents / 100,
                                              Math.abs(cents % 100));
                w.write(date + "," + type + "," + cents + ",\"" + amount
                      + "\",\"" + peer + "\",\"" + memo + "\"," + status + "," + txId + "\n");
            }
            Log.i(TAG, "CSV exported: " + out.getAbsolutePath());
            return out;
        } catch (IOException e) {
            Log.e(TAG, "CSV export failed", e);
            return null;
        }
    }

    /** Export transactions as JSON array. Returns the created File, or null on failure. */
    public static File exportJson(List<ShongololoTransaction> txs, File downloadDir) {
        File out = new File(downloadDir, buildFilename("json"));
        try (FileWriter w = new FileWriter(out, false)) {
            w.write("[\n");
            for (int i = 0; i < txs.size(); i++) {
                ShongololoTransaction tx = txs.get(i);
                String type = tx.type == ShongololoTransaction.TYPE_SEND ? "SENT" : "RECEIVED";
                String peer = tx.type == ShongololoTransaction.TYPE_SEND
                              ? tx.receiverPubkey : tx.senderDeviceId;
                w.write("  {");
                w.write("\"ts\":" + tx.createdAtMs + ",");
                w.write("\"type\":\"" + type + "\",");
                w.write("\"amountCents\":" + tx.amountCents + ",");
                w.write("\"peer\":\"" + jsonEsc(peer) + "\",");
                w.write("\"memo\":\"" + jsonEsc(tx.memo) + "\",");
                w.write("\"status\":\"" + statusName(tx.status) + "\",");
                w.write("\"txId\":\"" + jsonEsc(tx.txId) + "\"");
                w.write(i < txs.size() - 1 ? "},\n" : "}\n");
            }
            w.write("]");
            Log.i(TAG, "JSON exported: " + out.getAbsolutePath());
            return out;
        } catch (IOException e) {
            Log.e(TAG, "JSON export failed", e);
            return null;
        }
    }

    // ── Helpers ───────────────────────────────────────────────

    private static String buildFilename(String ext) {
        String ts = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
        return "shongololo_" + ts + "." + ext;
    }

    private static String safe(String s) {
        return s != null ? s.replace("\"", "\"\"") : "";
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String statusName(int status) {
        switch (status) {
            case ShongololoTransaction.STATUS_SETTLED:            return "settled";
            case ShongololoTransaction.STATUS_PENDING_SETTLEMENT: return "pending";
            case ShongololoTransaction.STATUS_REVERSED:           return "reversed";
            case ShongololoTransaction.STATUS_REJECTED:           return "rejected";
            default:                                              return "unknown";
        }
    }
}
