/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.security;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.List;

public final class DmzAnalysisResult implements Parcelable {

    // Verdict constants
    public static final int VERDICT_CLEAN        = 0;
    public static final int VERDICT_SUSPICIOUS   = 1;
    public static final int VERDICT_THREAT       = 2;
    public static final int VERDICT_SANITIZED    = 3; // CDR produced clean version
    public static final int VERDICT_ERROR        = 4;

    // Stage constants
    public static final int STAGE_INTAKE         = 1;
    public static final int STAGE_STATIC         = 2;
    public static final int STAGE_SANDBOXED      = 3;
    public static final int STAGE_CDR            = 4;
    public static final int STAGE_BEHAVIORAL     = 5;

    // Error codes
    public static final int ERROR_NONE           = 0;
    public static final int ERROR_TIMEOUT        = 1;
    public static final int ERROR_OOM            = 2;
    public static final int ERROR_UNSUPPORTED    = 3;
    public static final int ERROR_INTERNAL       = 99;

    public String  sessionId;
    public String  fileName;
    public String  mimeType;
    public String  sourceApp;
    public int     verdict;          // VERDICT_* constant
    public int     stageReached;     // STAGE_* constant
    public long    analysisDurationMs;
    public long    fileSizeBytes;
    public String  sha256;
    public boolean hasSanitizedVersion;  // CDR produced a clean file
    public boolean knownMaliciousHash;
    public List<String> findings;    // Human-readable findings for UI
    public List<String> c2Addresses; // Extracted C2 IPs/domains (if behavioral ran)
    public int     errorCode;

    public DmzAnalysisResult() {
        findings    = new ArrayList<>();
        c2Addresses = new ArrayList<>();
    }

    protected DmzAnalysisResult(Parcel in) {
        sessionId           = in.readString();
        fileName            = in.readString();
        mimeType            = in.readString();
        sourceApp           = in.readString();
        verdict             = in.readInt();
        stageReached        = in.readInt();
        analysisDurationMs  = in.readLong();
        fileSizeBytes       = in.readLong();
        sha256              = in.readString();
        hasSanitizedVersion = in.readByte() != 0;
        knownMaliciousHash  = in.readByte() != 0;
        findings            = new ArrayList<>();
        in.readStringList(findings);
        c2Addresses         = new ArrayList<>();
        in.readStringList(c2Addresses);
        errorCode           = in.readInt();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(sessionId);
        dest.writeString(fileName);
        dest.writeString(mimeType);
        dest.writeString(sourceApp);
        dest.writeInt(verdict);
        dest.writeInt(stageReached);
        dest.writeLong(analysisDurationMs);
        dest.writeLong(fileSizeBytes);
        dest.writeString(sha256);
        dest.writeByte((byte)(hasSanitizedVersion ? 1 : 0));
        dest.writeByte((byte)(knownMaliciousHash ? 1 : 0));
        dest.writeStringList(findings);
        dest.writeStringList(c2Addresses);
        dest.writeInt(errorCode);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<DmzAnalysisResult> CREATOR = new Creator<DmzAnalysisResult>() {
        @Override public DmzAnalysisResult createFromParcel(Parcel in) { return new DmzAnalysisResult(in); }
        @Override public DmzAnalysisResult[] newArray(int size) { return new DmzAnalysisResult[size]; }
    };
}
