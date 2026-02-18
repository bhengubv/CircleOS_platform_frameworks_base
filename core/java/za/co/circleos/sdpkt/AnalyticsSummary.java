/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Aggregated transaction analytics for the wallet dashboard.
 *
 * All monetary values are in cents (₷ × 100). The weekly arrays cover
 * the last 7 calendar days, index 0 = oldest, index 6 = today.
 */
public final class AnalyticsSummary implements Parcelable {

    public long   totalSentCents;
    public long   totalReceivedCents;
    public int    txCount;
    public int    txSentCount;
    public int    txReceivedCount;
    /** Average sent transaction value (cents). */
    public long   avgSentCents;
    /** Sent spend per day for the last 7 days (index 0 = oldest). */
    public long[] weeklySpentCents  = new long[7];
    /** Received per day for the last 7 days. */
    public long[] weeklyReceivedCents = new long[7];
    /** Peak single-day spend (cents) in the last 7 days. */
    public long   peakDaySpentCents;
    /** Short peer address/label of most-paid recipient (may be null). */
    public String topPeerShort;
    /** Number of transactions that triggered protection blocks. */
    public int    blockedTxCount;

    public AnalyticsSummary() {}

    protected AnalyticsSummary(Parcel in) {
        totalSentCents        = in.readLong();
        totalReceivedCents    = in.readLong();
        txCount               = in.readInt();
        txSentCount           = in.readInt();
        txReceivedCount       = in.readInt();
        avgSentCents          = in.readLong();
        in.readLongArray(weeklySpentCents);
        in.readLongArray(weeklyReceivedCents);
        peakDaySpentCents     = in.readLong();
        topPeerShort          = in.readString();
        blockedTxCount        = in.readInt();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(totalSentCents);
        dest.writeLong(totalReceivedCents);
        dest.writeInt(txCount);
        dest.writeInt(txSentCount);
        dest.writeInt(txReceivedCount);
        dest.writeLong(avgSentCents);
        dest.writeLongArray(weeklySpentCents);
        dest.writeLongArray(weeklyReceivedCents);
        dest.writeLong(peakDaySpentCents);
        dest.writeString(topPeerShort);
        dest.writeInt(blockedTxCount);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<AnalyticsSummary> CREATOR = new Creator<AnalyticsSummary>() {
        @Override public AnalyticsSummary createFromParcel(Parcel in) { return new AnalyticsSummary(in); }
        @Override public AnalyticsSummary[] newArray(int size)        { return new AnalyticsSummary[size]; }
    };
}
