/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Describes a per-mode app visibility rule.
 */
public final class AppRule implements Parcelable {

    /** Show the app in the launcher (default). */
    public static final int ACTION_SHOW    = 0;
    /** Hide the app from the launcher; it remains functional. */
    public static final int ACTION_HIDE    = 1;
    /** Disable the app entirely while this mode is active. */
    public static final int ACTION_DISABLE = 2;

    public String packageName;
    public int    action; // ACTION_* constant

    public AppRule() {}

    public AppRule(String packageName, int action) {
        this.packageName = packageName;
        this.action      = action;
    }

    protected AppRule(Parcel in) {
        packageName = in.readString();
        action      = in.readInt();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(packageName);
        dest.writeInt(action);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<AppRule> CREATOR = new Creator<AppRule>() {
        @Override public AppRule createFromParcel(Parcel in) { return new AppRule(in); }
        @Override public AppRule[] newArray(int size)        { return new AppRule[size]; }
    };
}
