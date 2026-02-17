/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.security;

import android.os.Parcel;
import android.os.Parcelable;

public final class ThreatIndicator implements Parcelable {

    public static final int TYPE_IP_ADDRESS  = 1;
    public static final int TYPE_DOMAIN      = 2;
    public static final int TYPE_FILE_HASH   = 3;
    public static final int TYPE_TLS_FP      = 4;  // TLS fingerprint
    public static final int TYPE_BEACON      = 5;  // Beacon pattern

    public static final int CONFIDENCE_LOW    = 1;
    public static final int CONFIDENCE_MEDIUM = 2;
    public static final int CONFIDENCE_HIGH   = 3;

    public int    type;
    public String value;       // The actual indicator (IP, domain, hash, etc.)
    public int    confidence;
    public String source;      // Feed name or "device"
    public long   firstSeen;   // epoch ms
    public long   lastSeen;    // epoch ms
    public String description;

    public ThreatIndicator() {}

    protected ThreatIndicator(Parcel in) {
        type        = in.readInt();
        value       = in.readString();
        confidence  = in.readInt();
        source      = in.readString();
        firstSeen   = in.readLong();
        lastSeen    = in.readLong();
        description = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(type);
        dest.writeString(value);
        dest.writeInt(confidence);
        dest.writeString(source);
        dest.writeLong(firstSeen);
        dest.writeLong(lastSeen);
        dest.writeString(description);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<ThreatIndicator> CREATOR = new Creator<ThreatIndicator>() {
        @Override public ThreatIndicator createFromParcel(Parcel in) { return new ThreatIndicator(in); }
        @Override public ThreatIndicator[] newArray(int size) { return new ThreatIndicator[size]; }
    };
}
