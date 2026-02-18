/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * A single protection-engine event recorded in the protection log.
 *
 * Events cover both blocked transfers and cleared protection states,
 * giving the user a transparent audit trail of how the system acted
 * on their behalf.
 */
public final class ProtectionEvent implements Parcelable {

    /** Transfer blocked because stress score exceeded threshold. */
    public static final int TYPE_STRESS_BLOCK    = 0;
    /** Transfer blocked because amount exceeded location-based limit. */
    public static final int TYPE_LOCATION_BLOCK  = 1;
    /** Transfer blocked because per-tap or daily limit was exceeded. */
    public static final int TYPE_LIMIT_BLOCK     = 2;
    /** Stress protection cleared (manually by user or by cooldown). */
    public static final int TYPE_STRESS_CLEARED  = 3;
    /** User reported a false positive and adjusted sensitivity. */
    public static final int TYPE_CALIBRATION_ADJ = 4;

    public int    type;
    public long   timestampMs;
    /** Amount of the blocked transfer (cents); 0 for non-block events. */
    public long   amountCents;
    /** Human-readable reason (e.g. "stress score 82 > 70"). */
    public String reason;
    /** Location label at time of event (may be null). */
    public String locationLabel;

    public ProtectionEvent() {}

    protected ProtectionEvent(Parcel in) {
        type          = in.readInt();
        timestampMs   = in.readLong();
        amountCents   = in.readLong();
        reason        = in.readString();
        locationLabel = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(type);
        dest.writeLong(timestampMs);
        dest.writeLong(amountCents);
        dest.writeString(reason);
        dest.writeString(locationLabel);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<ProtectionEvent> CREATOR = new Creator<ProtectionEvent>() {
        @Override public ProtectionEvent createFromParcel(Parcel in) { return new ProtectionEvent(in); }
        @Override public ProtectionEvent[] newArray(int size)        { return new ProtectionEvent[size]; }
    };

    public String typeName() {
        switch (type) {
            case TYPE_STRESS_BLOCK:    return "Stress block";
            case TYPE_LOCATION_BLOCK:  return "Location block";
            case TYPE_LIMIT_BLOCK:     return "Limit block";
            case TYPE_STRESS_CLEARED:  return "Stress cleared";
            case TYPE_CALIBRATION_ADJ: return "Calibration adjusted";
            default:                   return "Unknown";
        }
    }
}
