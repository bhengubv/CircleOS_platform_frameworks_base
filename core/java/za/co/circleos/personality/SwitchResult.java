/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Result returned by {@code ICirclePersonalityManager#activateMode} and
 * {@code activatePreviousMode}.
 */
public final class SwitchResult implements Parcelable {

    public boolean success;
    public String  previousModeId; // null if no previous mode
    public String  newModeId;
    public String  errorMessage;   // null on success

    public SwitchResult() {}

    public static SwitchResult ok(String previousModeId, String newModeId) {
        SwitchResult r = new SwitchResult();
        r.success       = true;
        r.previousModeId = previousModeId;
        r.newModeId      = newModeId;
        return r;
    }

    public static SwitchResult fail(String error) {
        SwitchResult r = new SwitchResult();
        r.success      = false;
        r.errorMessage = error;
        return r;
    }

    protected SwitchResult(Parcel in) {
        success        = in.readByte() != 0;
        previousModeId = in.readString();
        newModeId      = in.readString();
        errorMessage   = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeByte((byte) (success ? 1 : 0));
        dest.writeString(previousModeId);
        dest.writeString(newModeId);
        dest.writeString(errorMessage);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<SwitchResult> CREATOR = new Creator<SwitchResult>() {
        @Override public SwitchResult createFromParcel(Parcel in) { return new SwitchResult(in); }
        @Override public SwitchResult[] newArray(int size)        { return new SwitchResult[size]; }
    };
}
