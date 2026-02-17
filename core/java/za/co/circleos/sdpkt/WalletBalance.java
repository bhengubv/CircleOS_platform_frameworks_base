/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Current wallet balance snapshot.
 *
 * availableCents      — settled balance (safe to spend)
 * pendingInCents      — received offline, not yet network-confirmed
 * pendingOutCents     — sent offline, not yet network-confirmed
 * offlineSpentCents   — total offline spending since last sync (tracked against ₷5,000 cap)
 * dailySpentCents     — spending in the current 24h window
 * dailyLimitCents     — current daily limit (affected by location/protection)
 */
public final class WalletBalance implements Parcelable {

    public long availableCents;      // settled, spendable
    public long pendingInCents;      // pending inbound (unconfirmed receives)
    public long pendingOutCents;     // pending outbound (unconfirmed sends)
    public long offlineSpentCents;   // offline accumulation since last sync
    public long dailySpentCents;     // spending in current 24h window
    public long dailyLimitCents;     // effective daily limit
    public long perTapLimitCents;    // effective per-tap limit
    public long snapshotMs;          // epoch ms when this balance was computed

    public WalletBalance() {}

    /** Display-friendly available balance string. */
    public String formattedAvailable() {
        return String.format("₷%d.%02d", availableCents / 100, availableCents % 100);
    }

    /** Remaining offline capacity before sync is required. */
    public long offlineRemainingCents() {
        long cap = 500_000L; // ₷5,000 default
        return Math.max(0, cap - offlineSpentCents);
    }

    /** Remaining daily allowance. */
    public long dailyRemainingCents() {
        return Math.max(0, dailyLimitCents - dailySpentCents);
    }

    protected WalletBalance(Parcel in) {
        availableCents    = in.readLong();
        pendingInCents    = in.readLong();
        pendingOutCents   = in.readLong();
        offlineSpentCents = in.readLong();
        dailySpentCents   = in.readLong();
        dailyLimitCents   = in.readLong();
        perTapLimitCents  = in.readLong();
        snapshotMs        = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(availableCents);
        dest.writeLong(pendingInCents);
        dest.writeLong(pendingOutCents);
        dest.writeLong(offlineSpentCents);
        dest.writeLong(dailySpentCents);
        dest.writeLong(dailyLimitCents);
        dest.writeLong(perTapLimitCents);
        dest.writeLong(snapshotMs);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<WalletBalance> CREATOR = new Creator<WalletBalance>() {
        @Override public WalletBalance createFromParcel(Parcel in) { return new WalletBalance(in); }
        @Override public WalletBalance[] newArray(int size) { return new WalletBalance[size]; }
    };
}
