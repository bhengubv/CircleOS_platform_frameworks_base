/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.compression;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Monthly compression statistics — used by the user-facing dashboard.
 *
 * Tracks inbound/outbound bytes saved, storage savings, and cross-referenced
 * security event counts (populated by CircleFileDmzService).
 */
public final class CompressionStats implements Parcelable {

    public long inboundOriginalBytes;
    public long inboundCompressedBytes;

    public long outboundOriginalBytes;
    public long outboundCompressedBytes;

    public long storageOriginalBytes;
    public long storageCompressedBytes;

    /** Cross-referenced from CircleFileDmzService — for the dashboard. */
    public int  filesCompressed;
    public int  metadataStrippedCount;
    public int  deduplicatedCount;

    public long periodStartMs;
    public long periodEndMs;

    public CompressionStats() {}

    /** Convenience: total bytes saved across inbound + outbound. */
    public long totalSavedBytes() {
        return (inboundOriginalBytes  - inboundCompressedBytes)
             + (outboundOriginalBytes - outboundCompressedBytes);
    }

    /** Overall savings percent across inbound + outbound. */
    public int overallSavingsPercent() {
        long total = inboundOriginalBytes + outboundOriginalBytes;
        if (total == 0) return 0;
        return (int) (totalSavedBytes() * 100L / total);
    }

    protected CompressionStats(Parcel in) {
        inboundOriginalBytes    = in.readLong();
        inboundCompressedBytes  = in.readLong();
        outboundOriginalBytes   = in.readLong();
        outboundCompressedBytes = in.readLong();
        storageOriginalBytes    = in.readLong();
        storageCompressedBytes  = in.readLong();
        filesCompressed         = in.readInt();
        metadataStrippedCount   = in.readInt();
        deduplicatedCount       = in.readInt();
        periodStartMs           = in.readLong();
        periodEndMs             = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(inboundOriginalBytes);
        dest.writeLong(inboundCompressedBytes);
        dest.writeLong(outboundOriginalBytes);
        dest.writeLong(outboundCompressedBytes);
        dest.writeLong(storageOriginalBytes);
        dest.writeLong(storageCompressedBytes);
        dest.writeInt(filesCompressed);
        dest.writeInt(metadataStrippedCount);
        dest.writeInt(deduplicatedCount);
        dest.writeLong(periodStartMs);
        dest.writeLong(periodEndMs);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<CompressionStats> CREATOR = new Creator<CompressionStats>() {
        @Override public CompressionStats createFromParcel(Parcel in) { return new CompressionStats(in); }
        @Override public CompressionStats[] newArray(int size) { return new CompressionStats[size]; }
    };
}
