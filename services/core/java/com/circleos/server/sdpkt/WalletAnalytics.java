/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import za.co.circleos.sdpkt.AnalyticsSummary;
import za.co.circleos.sdpkt.ShongololoTransaction;

/**
 * Derives {@link AnalyticsSummary} from the in-memory transaction history.
 *
 * All computation is performed on the caller's thread; no I/O.
 */
public final class WalletAnalytics {

    private WalletAnalytics() {}

    /**
     * Build a summary from a list of transactions (all time for totals,
     * last 7 calendar days for weekly arrays).
     *
     * @param txs            Full transaction history (most-recent-first order expected).
     * @param blockedCount   Number of protection-blocked transfer attempts.
     */
    public static AnalyticsSummary compute(List<ShongololoTransaction> txs, int blockedCount) {
        AnalyticsSummary s = new AnalyticsSummary();
        s.blockedTxCount = blockedCount;

        if (txs == null || txs.isEmpty()) return s;

        // Day-of-epoch index helpers for last-7-days bucketing
        long nowMs         = System.currentTimeMillis();
        long todayEpochDay = dayEpoch(nowMs);
        long sevenDaysAgo  = todayEpochDay - 6;  // inclusive

        Map<String, Long> peerSpend = new HashMap<>();

        for (ShongololoTransaction tx : txs) {
            boolean sent = tx.type == ShongololoTransaction.TYPE_SEND;
            s.txCount++;

            if (sent) {
                s.txSentCount++;
                s.totalSentCents += tx.amountCents;
                // peer tracking for top-peer
                String peer = tx.receiverPubkey;
                if (peer != null && !peer.isEmpty()) {
                    peerSpend.merge(peer, tx.amountCents, Long::sum);
                }
                // weekly bucket
                long day = dayEpoch(tx.createdAtMs);
                if (day >= sevenDaysAgo && day <= todayEpochDay) {
                    int idx = (int) (day - sevenDaysAgo);
                    s.weeklySpentCents[idx] += tx.amountCents;
                }
            } else {
                s.txReceivedCount++;
                s.totalReceivedCents += tx.amountCents;
                long day = dayEpoch(tx.createdAtMs);
                if (day >= sevenDaysAgo && day <= todayEpochDay) {
                    int idx = (int) (day - sevenDaysAgo);
                    s.weeklyReceivedCents[idx] += tx.amountCents;
                }
            }
        }

        // Averages and peaks
        if (s.txSentCount > 0) {
            s.avgSentCents = s.totalSentCents / s.txSentCount;
        }
        for (long v : s.weeklySpentCents) {
            if (v > s.peakDaySpentCents) s.peakDaySpentCents = v;
        }

        // Top peer
        String topPeer = null;
        long topAmount = 0;
        for (Map.Entry<String, Long> e : peerSpend.entrySet()) {
            if (e.getValue() > topAmount) {
                topAmount = e.getValue();
                topPeer   = e.getKey();
            }
        }
        if (topPeer != null) {
            s.topPeerShort = topPeer.length() > 8 ? topPeer.substring(0, 8) + "…" : topPeer;
        }

        return s;
    }

    /** Returns the number of calendar days since Unix epoch for a given timestamp. */
    private static long dayEpoch(long ms) {
        Calendar c = Calendar.getInstance();
        c.setTimeInMillis(ms);
        // Compute days manually to avoid TZ complexity
        return ms / 86_400_000L;
    }
}
