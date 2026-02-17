/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Describes a personality mode (profile) that can be activated on a CircleOS device.
 */
public final class PersonalityMode implements Parcelable {

    public String     id;          // e.g. "daily", "work", "secure"
    public String     name;        // Display name, e.g. "Daily"
    public String     description; // One-line summary shown in UI
    public int        tier;        // 1=bundled, 2=download-on-activation, 3=specialist
    public ModeConfig config;      // Settings applied when this mode is active

    public PersonalityMode() {}

    protected PersonalityMode(Parcel in) {
        id          = in.readString();
        name        = in.readString();
        description = in.readString();
        tier        = in.readInt();
        config      = in.readParcelable(ModeConfig.class.getClassLoader());
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(id);
        dest.writeString(name);
        dest.writeString(description);
        dest.writeInt(tier);
        dest.writeParcelable(config, flags);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<PersonalityMode> CREATOR = new Creator<PersonalityMode>() {
        @Override public PersonalityMode createFromParcel(Parcel in) { return new PersonalityMode(in); }
        @Override public PersonalityMode[] newArray(int size)        { return new PersonalityMode[size]; }
    };
}
