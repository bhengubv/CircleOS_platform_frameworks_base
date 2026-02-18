/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Current location context used to determine transaction limits.
 *
 * Limit table (default values, cents):
 *   HOME    — per-tap ₷5,000 / daily ₷20,000
 *   KNOWN   — per-tap ₷2,000 / daily ₷10,000
 *   UNKNOWN — per-tap ₷500   / daily ₷2,000
 *   RISKY   — per-tap ₷200   / daily ₷500
 *   MOVING  — per-tap ₷100   / daily ₷500
 */
public final class LocationContext implements Parcelable {

    /** Recognised home location (>= 5 visits + auto-detected). */
    public static final int TYPE_HOME    = 0;
    /** Recognised and frequently-visited location (>= 5 visits). */
    public static final int TYPE_KNOWN   = 1;
    /** Location seen fewer than 5 times — lower limits apply. */
    public static final int TYPE_UNKNOWN = 2;
    /** Location flagged as risky by the learning engine. */
    public static final int TYPE_RISKY   = 3;
    /** Device moving faster than 30 km/h. */
    public static final int TYPE_MOVING  = 4;

    /* ── Default limits (cents) per context type ──────────── */
    public static final long HOME_PER_TAP_CENTS    =  500_000L; // ₷5,000
    public static final long HOME_DAILY_CENTS       = 2_000_000L; // ₷20,000
    public static final long KNOWN_PER_TAP_CENTS   =  200_000L; // ₷2,000
    public static final long KNOWN_DAILY_CENTS      = 1_000_000L; // ₷10,000
    public static final long UNKNOWN_PER_TAP_CENTS =   50_000L; // ₷500
    public static final long UNKNOWN_DAILY_CENTS    =  200_000L; // ₷2,000
    public static final long RISKY_PER_TAP_CENTS   =   20_000L; // ₷200
    public static final long RISKY_DAILY_CENTS      =   50_000L; // ₷500
    public static final long MOVING_PER_TAP_CENTS  =   10_000L; // ₷100
    public static final long MOVING_DAILY_CENTS     =   50_000L; // ₷500

    public int    type;                // TYPE_* constant
    public long   perTapLimitCents;
    public long   dailyLimitCents;
    public float  confidencePercent;   // 0–100
    public String locationLabel;       // "Home", "Work", "Mall", "", …
    public float  speedMs;             // current speed in m/s (0 if stationary)
    public long   snapshotMs;          // time of this snapshot

    public LocationContext() {}

    /** Build a context snapshot for the given type with default limits. */
    public static LocationContext forType(int type, String label, float confidence) {
        LocationContext c = new LocationContext();
        c.type              = type;
        c.locationLabel     = label != null ? label : "";
        c.confidencePercent = confidence;
        c.snapshotMs        = System.currentTimeMillis();
        switch (type) {
            case TYPE_HOME:
                c.perTapLimitCents = HOME_PER_TAP_CENTS;
                c.dailyLimitCents  = HOME_DAILY_CENTS;
                break;
            case TYPE_KNOWN:
                c.perTapLimitCents = KNOWN_PER_TAP_CENTS;
                c.dailyLimitCents  = KNOWN_DAILY_CENTS;
                break;
            case TYPE_RISKY:
                c.perTapLimitCents = RISKY_PER_TAP_CENTS;
                c.dailyLimitCents  = RISKY_DAILY_CENTS;
                break;
            case TYPE_MOVING:
                c.perTapLimitCents = MOVING_PER_TAP_CENTS;
                c.dailyLimitCents  = MOVING_DAILY_CENTS;
                break;
            default: // UNKNOWN
                c.perTapLimitCents = UNKNOWN_PER_TAP_CENTS;
                c.dailyLimitCents  = UNKNOWN_DAILY_CENTS;
                break;
        }
        return c;
    }

    public String typeName() {
        switch (type) {
            case TYPE_HOME:    return "Home";
            case TYPE_KNOWN:   return "Known";
            case TYPE_RISKY:   return "Risky";
            case TYPE_MOVING:  return "Moving";
            default:           return "Unknown";
        }
    }

    // ── Parcelable ─────────────────────────────────────────

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(type);
        dest.writeLong(perTapLimitCents);
        dest.writeLong(dailyLimitCents);
        dest.writeFloat(confidencePercent);
        dest.writeString(locationLabel);
        dest.writeFloat(speedMs);
        dest.writeLong(snapshotMs);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<LocationContext> CREATOR = new Creator<LocationContext>() {
        @Override public LocationContext createFromParcel(Parcel in) {
            LocationContext c = new LocationContext();
            c.type              = in.readInt();
            c.perTapLimitCents  = in.readLong();
            c.dailyLimitCents   = in.readLong();
            c.confidencePercent = in.readFloat();
            c.locationLabel     = in.readString();
            c.speedMs           = in.readFloat();
            c.snapshotMs        = in.readLong();
            return c;
        }
        @Override public LocationContext[] newArray(int size) { return new LocationContext[size]; }
    };
}
