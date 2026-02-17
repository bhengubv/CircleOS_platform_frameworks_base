/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.List;

public final class ModeBundle implements Parcelable {
    public String      bundleId;
    public String      modeId;
    public String      displayName;
    public long        sizeBytes;
    public String      downloadUrl;
    public List<String> requiredApps;
    public List<String> recommendedApps;
    public boolean     isDownloaded;
    public int         downloadProgress; // 0-100, -1 = not started
    public String      localPath;

    public ModeBundle() {
        requiredApps    = new ArrayList<>();
        recommendedApps = new ArrayList<>();
        downloadProgress = -1;
    }

    protected ModeBundle(Parcel in) {
        bundleId         = in.readString();
        modeId           = in.readString();
        displayName      = in.readString();
        sizeBytes        = in.readLong();
        downloadUrl      = in.readString();
        requiredApps     = in.createStringArrayList();
        recommendedApps  = in.createStringArrayList();
        isDownloaded     = in.readByte() != 0;
        downloadProgress = in.readInt();
        localPath        = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(bundleId);
        dest.writeString(modeId);
        dest.writeString(displayName);
        dest.writeLong(sizeBytes);
        dest.writeString(downloadUrl);
        dest.writeStringList(requiredApps);
        dest.writeStringList(recommendedApps);
        dest.writeByte((byte)(isDownloaded ? 1 : 0));
        dest.writeInt(downloadProgress);
        dest.writeString(localPath);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<ModeBundle> CREATOR = new Creator<ModeBundle>() {
        @Override public ModeBundle createFromParcel(Parcel in) { return new ModeBundle(in); }
        @Override public ModeBundle[] newArray(int size)        { return new ModeBundle[size]; }
    };
}
