/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Current sync state for the SDPKT settlement queue.
 *
 * Transitions:
 *   OFFLINE → ONLINE_PENDING (network available, queue non-empty)
 *   ONLINE_PENDING → SYNCING (drain started)
 *   SYNCING → SYNCED (queue empty)
 *   SYNCED → OFFLINE (network lost)
 *
 * Errors: failedCount > 0 while state = SYNCED means some transactions
 * could not be settled and have been reversed.
 */
public final class SyncStatus implements Parcelable {

    /** No network — outbound transactions accumulate in the queue. */
    public static final int STATE_OFFLINE        = 0;
    /** Network available, pending transactions waiting to settle. */
    public static final int STATE_ONLINE_PENDING = 1;
    /** Actively draining the settlement queue. */
    public static final int STATE_SYNCING        = 2;
    /** All pending transactions settled; queue empty. */
    public static final int STATE_SYNCED         = 3;

    public int  state;           // STATE_* constant
    public int  pendingCount;    // outbound transactions awaiting settlement
    public int  failedCount;     // transactions reversed since last sync
    public long lastSyncMs;      // epoch ms of last successful sync (0 if never)
    public long offlineSinceMs;  // epoch ms when device went offline (0 if online)

    public SyncStatus() {}

    // ── Parcelable ────────────────────────────────────────

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(state);
        dest.writeInt(pendingCount);
        dest.writeInt(failedCount);
        dest.writeLong(lastSyncMs);
        dest.writeLong(offlineSinceMs);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<SyncStatus> CREATOR = new Creator<SyncStatus>() {
        @Override public SyncStatus createFromParcel(Parcel in) {
            SyncStatus s = new SyncStatus();
            s.state          = in.readInt();
            s.pendingCount   = in.readInt();
            s.failedCount    = in.readInt();
            s.lastSyncMs     = in.readLong();
            s.offlineSinceMs = in.readLong();
            return s;
        }
        @Override public SyncStatus[] newArray(int size) { return new SyncStatus[size]; }
    };
}
