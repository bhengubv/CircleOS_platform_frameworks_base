/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Result of an attempted Shongololo transaction.
 */
public final class TransactionResult implements Parcelable {

    /* ── Error codes ─────────────────────────────────── */
    public static final int OK                    = 0;
    public static final int ERR_INSUFFICIENT_FUNDS = 1;
    public static final int ERR_LIMIT_EXCEEDED     = 2;   // per-tap or daily limit
    public static final int ERR_OFFLINE_LIMIT      = 3;   // offline accumulation cap
    public static final int ERR_PROTECTION_STRESS  = 4;   // Protection Engine: stress detected
    public static final int ERR_PROTECTION_LOCATION= 5;   // Protection Engine: location limit
    public static final int ERR_INVALID_SIGNATURE  = 6;   // peer's signature invalid
    public static final int ERR_REPLAY             = 7;   // duplicate nonce / timestamp
    public static final int ERR_NO_WALLET          = 8;   // wallet not initialized
    public static final int ERR_NFC_TIMEOUT        = 9;   // NFC peer disconnected
    public static final int ERR_INTERNAL           = 99;

    public boolean success;
    public int     errorCode;      // ERR_* (0 = OK)
    public String  errorMessage;   // human-readable (for attacker: always generic)
    public String  txId;           // UUID of the transaction (set on success)
    public long    newBalanceCents; // updated balance after transaction
    public long    dailyRemainingCents; // remaining daily allowance

    public TransactionResult() {}

    /** Factory — success. */
    public static TransactionResult ok(String txId, long newBalanceCents, long dailyRemaining) {
        TransactionResult r = new TransactionResult();
        r.success              = true;
        r.errorCode            = OK;
        r.txId                 = txId;
        r.newBalanceCents      = newBalanceCents;
        r.dailyRemainingCents  = dailyRemaining;
        return r;
    }

    /** Factory — failure. errorMessage is what the *user* sees; attacker sees generic. */
    public static TransactionResult fail(int code, String message) {
        TransactionResult r = new TransactionResult();
        r.success      = false;
        r.errorCode    = code;
        r.errorMessage = message;
        return r;
    }

    protected TransactionResult(Parcel in) {
        success             = in.readByte() != 0;
        errorCode           = in.readInt();
        errorMessage        = in.readString();
        txId                = in.readString();
        newBalanceCents     = in.readLong();
        dailyRemainingCents = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeByte((byte) (success ? 1 : 0));
        dest.writeInt(errorCode);
        dest.writeString(errorMessage);
        dest.writeString(txId);
        dest.writeLong(newBalanceCents);
        dest.writeLong(dailyRemainingCents);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<TransactionResult> CREATOR = new Creator<TransactionResult>() {
        @Override public TransactionResult createFromParcel(Parcel in) { return new TransactionResult(in); }
        @Override public TransactionResult[] newArray(int size) { return new TransactionResult[size]; }
    };
}
