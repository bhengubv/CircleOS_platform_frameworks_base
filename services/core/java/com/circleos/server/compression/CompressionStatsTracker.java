/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.compression;

import android.content.Context;
import android.util.Log;

import za.co.circleos.compression.CompressionResult;
import za.co.circleos.compression.CompressionRequest;
import za.co.circleos.compression.CompressionStats;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Calendar;

/**
 * Tracks monthly compression statistics for the user-facing dashboard.
 *
 * Stats are persisted to /data/circle/compression/stats.json (flat JSON, one line)
 * and reset automatically when the calendar month rolls over.
 *
 * Thread-safety: all methods are synchronized.
 */
public class CompressionStatsTracker {

    private static final String TAG      = "CircleCompStats";
    private static final String STATS_DIR  = "/data/circle/compression/";
    private static final String STATS_FILE = STATS_DIR + "stats.json";

    private final Object mLock = new Object();

    private long mInboundOriginal;
    private long mInboundCompressed;
    private long mOutboundOriginal;
    private long mOutboundCompressed;
    private int  mFilesCompressed;
    private int  mMetadataStripped;
    private int  mDeduplicated;
    private long mPeriodStartMs;

    public CompressionStatsTracker(Context ctx) {
        new File(STATS_DIR).mkdirs();
        load();
        checkMonthRollover();
    }

    /** Record the result of a completed compression session. */
    public void record(CompressionResult result, int direction) {
        if (result.status != CompressionResult.STATUS_OK) return;
        synchronized (mLock) {
            checkMonthRollover();
            if (direction == CompressionRequest.DIRECTION_INBOUND) {
                mInboundOriginal    += result.originalBytes;
                mInboundCompressed  += result.compressedBytes;
            } else {
                mOutboundOriginal   += result.originalBytes;
                mOutboundCompressed += result.compressedBytes;
            }
            mFilesCompressed++;
            if (result.metadataStripped) mMetadataStripped++;
            if (result.deduplicated)     mDeduplicated++;
            persist();
        }
    }

    public CompressionStats getStats() {
        synchronized (mLock) {
            checkMonthRollover();
            CompressionStats s      = new CompressionStats();
            s.inboundOriginalBytes    = mInboundOriginal;
            s.inboundCompressedBytes  = mInboundCompressed;
            s.outboundOriginalBytes   = mOutboundOriginal;
            s.outboundCompressedBytes = mOutboundCompressed;
            s.filesCompressed         = mFilesCompressed;
            s.metadataStrippedCount   = mMetadataStripped;
            s.deduplicatedCount       = mDeduplicated;
            s.periodStartMs           = mPeriodStartMs;
            s.periodEndMs             = System.currentTimeMillis();
            return s;
        }
    }

    public void reset() {
        synchronized (mLock) {
            mInboundOriginal    = 0;
            mInboundCompressed  = 0;
            mOutboundOriginal   = 0;
            mOutboundCompressed = 0;
            mFilesCompressed    = 0;
            mMetadataStripped   = 0;
            mDeduplicated       = 0;
            mPeriodStartMs      = System.currentTimeMillis();
            persist();
            Log.i(TAG, "Monthly stats reset");
        }
    }

    /* ── Persistence ─────────────────────────────────────────────────── */

    private void checkMonthRollover() {
        if (mPeriodStartMs == 0) return;
        Calendar start = Calendar.getInstance();
        start.setTimeInMillis(mPeriodStartMs);
        Calendar now = Calendar.getInstance();
        if (now.get(Calendar.YEAR)  != start.get(Calendar.YEAR)
         || now.get(Calendar.MONTH) != start.get(Calendar.MONTH)) {
            Log.i(TAG, "Month rollover — resetting stats");
            reset();
        }
    }

    private void persist() {
        try (FileWriter fw = new FileWriter(STATS_FILE)) {
            fw.write("{\"io\":" + mInboundOriginal
                   + ",\"ic\":" + mInboundCompressed
                   + ",\"oo\":" + mOutboundOriginal
                   + ",\"oc\":" + mOutboundCompressed
                   + ",\"fc\":" + mFilesCompressed
                   + ",\"ms\":" + mMetadataStripped
                   + ",\"dd\":" + mDeduplicated
                   + ",\"ps\":" + mPeriodStartMs + "}");
        } catch (IOException e) {
            Log.e(TAG, "Stats persist failed", e);
        }
    }

    private void load() {
        File f = new File(STATS_FILE);
        if (!f.exists()) {
            mPeriodStartMs = System.currentTimeMillis();
            return;
        }
        try {
            char[] buf = new char[(int) f.length()];
            try (FileReader fr = new FileReader(f)) { fr.read(buf); }
            String json = new String(buf);
            mInboundOriginal   = jsonLong(json, "io");
            mInboundCompressed = jsonLong(json, "ic");
            mOutboundOriginal  = jsonLong(json, "oo");
            mOutboundCompressed= jsonLong(json, "oc");
            mFilesCompressed   = (int) jsonLong(json, "fc");
            mMetadataStripped  = (int) jsonLong(json, "ms");
            mDeduplicated      = (int) jsonLong(json, "dd");
            mPeriodStartMs     = jsonLong(json, "ps");
            Log.i(TAG, "Stats loaded — " + mFilesCompressed + " files compressed this month");
        } catch (Exception e) {
            Log.w(TAG, "Stats load failed — starting fresh", e);
            mPeriodStartMs = System.currentTimeMillis();
        }
    }

    /** Minimal JSON long extractor — avoids pulling in a JSON library. */
    private long jsonLong(String json, String key) {
        String marker = "\"" + key + "\":";
        int idx = json.indexOf(marker);
        if (idx < 0) return 0;
        idx += marker.length();
        int end = idx;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-'))
            end++;
        try { return Long.parseLong(json.substring(idx, end)); }
        catch (NumberFormatException e) { return 0; }
    }
}
