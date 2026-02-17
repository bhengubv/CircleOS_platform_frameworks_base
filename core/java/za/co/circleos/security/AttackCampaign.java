/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.security;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a correlated attack campaign — a cluster of related IOCs
 * attributed to the same threat actor or infrastructure.
 */
public final class AttackCampaign implements Parcelable {

    // Confidence level that IOCs belong to same campaign
    public static final int CONFIDENCE_LOW    = 1;
    public static final int CONFIDENCE_MEDIUM = 2;
    public static final int CONFIDENCE_HIGH   = 3;

    // Attribution hints (never definitive)
    public static final int ATTRIBUTION_UNKNOWN       = 0;
    public static final int ATTRIBUTION_NATION_STATE  = 1;
    public static final int ATTRIBUTION_CRIMINAL      = 2;
    public static final int ATTRIBUTION_HACKTIVIST    = 3;

    public String  campaignId;
    public String  name;           // e.g. "campaign-2024-0042"
    public String  description;
    public int     confidence;     // CONFIDENCE_*
    public int     attribution;    // ATTRIBUTION_*
    public long    firstSeenMs;    // epoch ms — earliest IOC timestamp
    public long    lastSeenMs;     // epoch ms — most recent IOC timestamp
    public int     affectedDevices; // estimated from community data
    public List<String> iocs;        // raw IOC values (IPs, domains, hashes)
    public List<String> ttps;        // MITRE ATT&CK technique IDs (T1xxx)
    public List<String> targetRegions; // ISO country codes of targeted regions
    public String  stixId;          // STIX 2.1 campaign UUID

    public AttackCampaign() {
        iocs          = new ArrayList<>();
        ttps          = new ArrayList<>();
        targetRegions = new ArrayList<>();
    }

    protected AttackCampaign(Parcel in) {
        campaignId      = in.readString();
        name            = in.readString();
        description     = in.readString();
        confidence      = in.readInt();
        attribution     = in.readInt();
        firstSeenMs     = in.readLong();
        lastSeenMs      = in.readLong();
        affectedDevices = in.readInt();
        iocs            = new ArrayList<>(); in.readStringList(iocs);
        ttps            = new ArrayList<>(); in.readStringList(ttps);
        targetRegions   = new ArrayList<>(); in.readStringList(targetRegions);
        stixId          = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(campaignId);
        dest.writeString(name);
        dest.writeString(description);
        dest.writeInt(confidence);
        dest.writeInt(attribution);
        dest.writeLong(firstSeenMs);
        dest.writeLong(lastSeenMs);
        dest.writeInt(affectedDevices);
        dest.writeStringList(iocs);
        dest.writeStringList(ttps);
        dest.writeStringList(targetRegions);
        dest.writeString(stixId);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<AttackCampaign> CREATOR = new Creator<AttackCampaign>() {
        @Override public AttackCampaign createFromParcel(Parcel in) { return new AttackCampaign(in); }
        @Override public AttackCampaign[] newArray(int size) { return new AttackCampaign[size]; }
    };
}
