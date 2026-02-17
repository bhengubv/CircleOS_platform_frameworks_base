/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.compression;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Parameters for a compression request.
 *
 * Quality tiers:
 *   TIER_LOSSLESS          — zero quality loss; documents, code, professional media
 *   TIER_VISUALLY_LOSSLESS — imperceptible loss; default for photos/casual sharing
 *   TIER_AGGRESSIVE        — noticeable if inspected; emergency/low-data/mesh mode
 *
 * Direction:
 *   INBOUND  — file arriving from network/other device (scan → CDR → compress)
 *   OUTBOUND — file leaving device (compress → scan → send)
 */
public final class CompressionRequest implements Parcelable {

    public static final int TIER_LOSSLESS          = 1;
    public static final int TIER_VISUALLY_LOSSLESS = 2;  // default
    public static final int TIER_AGGRESSIVE        = 3;

    public static final int DIRECTION_INBOUND  = 0;
    public static final int DIRECTION_OUTBOUND = 1;

    public int     tier;           // TIER_*
    public int     direction;      // DIRECTION_*
    public String  mimeType;       // hint for codec selection
    public boolean stripMetadata;  // strip EXIF/XMP/GPS; always true for outbound
    public boolean deduplicateCheck; // check local hash store before compressing

    public CompressionRequest() {
        tier            = TIER_VISUALLY_LOSSLESS;
        direction       = DIRECTION_INBOUND;
        stripMetadata   = true;
        deduplicateCheck = false;
    }

    protected CompressionRequest(Parcel in) {
        tier             = in.readInt();
        direction        = in.readInt();
        mimeType         = in.readString();
        stripMetadata    = in.readByte() != 0;
        deduplicateCheck = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(tier);
        dest.writeInt(direction);
        dest.writeString(mimeType);
        dest.writeByte((byte) (stripMetadata    ? 1 : 0));
        dest.writeByte((byte) (deduplicateCheck ? 1 : 0));
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<CompressionRequest> CREATOR = new Creator<CompressionRequest>() {
        @Override public CompressionRequest createFromParcel(Parcel in) { return new CompressionRequest(in); }
        @Override public CompressionRequest[] newArray(int size) { return new CompressionRequest[size]; }
    };
}
