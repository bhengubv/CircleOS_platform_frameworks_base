/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.security;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.List;

public final class QuarantineRecord implements Parcelable {

    // Threat class constants
    public static final int CLASS_MALWARE         = 1;
    public static final int CLASS_SPYWARE         = 2;
    public static final int CLASS_EXPLOIT         = 3;
    public static final int CLASS_SUSPICIOUS      = 4;
    public static final int CLASS_PUA             = 5; // Potentially Unwanted App

    public String  quarantineId;     // UUID
    public String  originalPath;     // Where the file came from
    public String  fileName;
    public String  mimeType;
    public String  sourceApp;        // Package name that received the file
    public String  sha256;
    public int     threatClass;      // CLASS_* constant
    public String  threatName;       // e.g. "Pegasus.dropper.001"
    public long    quarantinedAt;    // epoch ms
    public long    fileSizeBytes;
    public boolean submittedToFeed;  // IOCs sent to Community Defense
    public List<String> iocExtracted; // IOCs found during analysis

    public QuarantineRecord() {
        iocExtracted = new ArrayList<>();
    }

    protected QuarantineRecord(Parcel in) {
        quarantineId      = in.readString();
        originalPath      = in.readString();
        fileName          = in.readString();
        mimeType          = in.readString();
        sourceApp         = in.readString();
        sha256            = in.readString();
        threatClass       = in.readInt();
        threatName        = in.readString();
        quarantinedAt     = in.readLong();
        fileSizeBytes     = in.readLong();
        submittedToFeed   = in.readByte() != 0;
        iocExtracted      = new ArrayList<>();
        in.readStringList(iocExtracted);
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(quarantineId);
        dest.writeString(originalPath);
        dest.writeString(fileName);
        dest.writeString(mimeType);
        dest.writeString(sourceApp);
        dest.writeString(sha256);
        dest.writeInt(threatClass);
        dest.writeString(threatName);
        dest.writeLong(quarantinedAt);
        dest.writeLong(fileSizeBytes);
        dest.writeByte((byte)(submittedToFeed ? 1 : 0));
        dest.writeStringList(iocExtracted);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<QuarantineRecord> CREATOR = new Creator<QuarantineRecord>() {
        @Override public QuarantineRecord createFromParcel(Parcel in) { return new QuarantineRecord(in); }
        @Override public QuarantineRecord[] newArray(int size) { return new QuarantineRecord[size]; }
    };
}
