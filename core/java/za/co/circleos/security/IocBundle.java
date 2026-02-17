/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.security;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * STIX 2.1–compatible IOC bundle for the researcher API.
 *
 * The stixJson field contains a complete STIX 2.1 bundle serialized as JSON.
 * Callers can use this directly with any STIX-compatible tooling.
 *
 * Summary fields are provided for quick display without JSON parsing.
 */
public final class IocBundle implements Parcelable {

    public String  bundleId;       // UUID
    public String  stixJson;       // Full STIX 2.1 bundle as JSON string
    public long    generatedAtMs;  // epoch ms
    public int     iocCount;
    public int     campaignCount;
    public long    oldestIocMs;    // epoch ms of earliest IOC in bundle
    public long    newestIocMs;    // epoch ms of newest IOC in bundle

    public IocBundle() {}

    protected IocBundle(Parcel in) {
        bundleId       = in.readString();
        stixJson       = in.readString();
        generatedAtMs  = in.readLong();
        iocCount       = in.readInt();
        campaignCount  = in.readInt();
        oldestIocMs    = in.readLong();
        newestIocMs    = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(bundleId);
        dest.writeString(stixJson);
        dest.writeLong(generatedAtMs);
        dest.writeInt(iocCount);
        dest.writeInt(campaignCount);
        dest.writeLong(oldestIocMs);
        dest.writeLong(newestIocMs);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<IocBundle> CREATOR = new Creator<IocBundle>() {
        @Override public IocBundle createFromParcel(Parcel in) { return new IocBundle(in); }
        @Override public IocBundle[] newArray(int size) { return new IocBundle[size]; }
    };
}
