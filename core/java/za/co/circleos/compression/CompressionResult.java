/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.compression;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Result of a compression operation.
 *
 * status == STATUS_SKIPPED when the file is already at or near optimal size
 * (< 5% potential savings) — caller receives original unchanged.
 */
public final class CompressionResult implements Parcelable {

    public static final int STATUS_OK      = 0;
    public static final int STATUS_SKIPPED = 1;  // already optimal / not worth compressing
    public static final int STATUS_ERROR   = 2;

    public String  sessionId;
    public int     status;
    public long    originalBytes;
    public long    compressedBytes;
    public int     savingsPercent;   // 0–100
    public String  method;           // e.g. "jpeg85", "png-opt", "webp80", "zip-deflate9"
    public long    processingMs;
    public boolean metadataStripped;
    public boolean deduplicated;     // true if an identical local copy exists

    public CompressionResult() {}

    protected CompressionResult(Parcel in) {
        sessionId        = in.readString();
        status           = in.readInt();
        originalBytes    = in.readLong();
        compressedBytes  = in.readLong();
        savingsPercent   = in.readInt();
        method           = in.readString();
        processingMs     = in.readLong();
        metadataStripped = in.readByte() != 0;
        deduplicated     = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(sessionId);
        dest.writeInt(status);
        dest.writeLong(originalBytes);
        dest.writeLong(compressedBytes);
        dest.writeInt(savingsPercent);
        dest.writeString(method);
        dest.writeLong(processingMs);
        dest.writeByte((byte) (metadataStripped ? 1 : 0));
        dest.writeByte((byte) (deduplicated     ? 1 : 0));
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<CompressionResult> CREATOR = new Creator<CompressionResult>() {
        @Override public CompressionResult createFromParcel(Parcel in) { return new CompressionResult(in); }
        @Override public CompressionResult[] newArray(int size) { return new CompressionResult[size]; }
    };
}
