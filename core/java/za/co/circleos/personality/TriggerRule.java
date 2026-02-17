/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Describes an auto-switch trigger rule for the Personality Engine.
 *
 * <p>Rules are evaluated by {@code AutoSwitchManager} against the current device context.
 * When a rule fires, {@code ConflictResolver} picks the highest-priority winner and
 * {@code ModeManager} applies the resulting mode switch.</p>
 */
public final class TriggerRule implements Parcelable {

    /** Rule type: manual placeholder (highest priority, never stored) */
    public static final int TYPE_MANUAL   = 0;
    /** Rule type: time-of-day / day-of-week */
    public static final int TYPE_TIME     = 1;
    /** Rule type: battery level falls below threshold */
    public static final int TYPE_BATTERY  = 2;
    /** Rule type: calendar event keyword match */
    public static final int TYPE_CALENDAR = 3;
    /** Rule type: charging state changed */
    public static final int TYPE_CHARGING = 4;

    /** Priority weights used by ConflictResolver. */
    public static final int PRIORITY_MANUAL   = 90;
    public static final int PRIORITY_CALENDAR = 70;
    public static final int PRIORITY_TIME     = 50;
    public static final int PRIORITY_BATTERY  = 30;
    public static final int PRIORITY_CHARGING = 20;

    /** Unique rule identifier. */
    public String  id;

    /** Rule type. One of TYPE_* constants. */
    public int     type;

    /** Mode to activate when this rule fires. */
    public String  targetModeId;

    /** Priority override. Defaults to the TYPE_* default priority if 0. */
    public int     priority;

    /** Whether the rule is currently active. */
    public boolean enabled;

    // ---- TYPE_TIME fields ----

    /** Hour (0-23) at which to activate the mode. */
    public int startHour;

    /** Minute (0-59) at which to activate the mode. */
    public int startMinute;

    /** Hour (0-23) at which to revert to the previous mode (-1 = no auto-revert). */
    public int endHour;

    /** Minute (0-59) for end time. */
    public int endMinute;

    /**
     * Day-of-week bitmask. Bit 0 = Sunday, bit 1 = Monday, ..., bit 6 = Saturday.
     * 0 = every day.
     */
    public int daysOfWeek;

    // ---- TYPE_BATTERY fields ----

    /** Battery percentage below which to activate (e.g. 15). */
    public int batteryThreshold;

    // ---- TYPE_CALENDAR fields ----

    /** Keyword to match against event titles/descriptions (case-insensitive). */
    public String calendarKeyword;

    /** How many minutes before the event to activate the mode. */
    public int calendarLeadMinutes;

    // ---- TYPE_CHARGING fields ----

    /** If true, activate when charging starts. If false, activate when unplugged. */
    public boolean requireCharging;

    public TriggerRule() {
        enabled            = true;
        endHour            = -1;
        endMinute          = -1;
        calendarLeadMinutes = 5;
    }

    /** Convenience factory for a time-based rule. */
    public static TriggerRule forTime(String id, String targetModeId,
            int startHour, int startMinute, int daysOfWeek) {
        TriggerRule r   = new TriggerRule();
        r.id            = id;
        r.type          = TYPE_TIME;
        r.targetModeId  = targetModeId;
        r.priority      = PRIORITY_TIME;
        r.startHour     = startHour;
        r.startMinute   = startMinute;
        r.daysOfWeek    = daysOfWeek;
        return r;
    }

    /** Convenience factory for a battery-level rule. */
    public static TriggerRule forBattery(String id, String targetModeId, int threshold) {
        TriggerRule r    = new TriggerRule();
        r.id             = id;
        r.type           = TYPE_BATTERY;
        r.targetModeId   = targetModeId;
        r.priority       = PRIORITY_BATTERY;
        r.batteryThreshold = threshold;
        return r;
    }

    /** Effective priority: explicit priority field if set, else TYPE default. */
    public int effectivePriority() {
        if (priority > 0) return priority;
        switch (type) {
            case TYPE_CALENDAR: return PRIORITY_CALENDAR;
            case TYPE_TIME:     return PRIORITY_TIME;
            case TYPE_BATTERY:  return PRIORITY_BATTERY;
            case TYPE_CHARGING: return PRIORITY_CHARGING;
            default:            return PRIORITY_MANUAL;
        }
    }

    protected TriggerRule(Parcel in) {
        id                  = in.readString();
        type                = in.readInt();
        targetModeId        = in.readString();
        priority            = in.readInt();
        enabled             = in.readByte() != 0;
        startHour           = in.readInt();
        startMinute         = in.readInt();
        endHour             = in.readInt();
        endMinute           = in.readInt();
        daysOfWeek          = in.readInt();
        batteryThreshold    = in.readInt();
        calendarKeyword     = in.readString();
        calendarLeadMinutes = in.readInt();
        requireCharging     = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(id);
        dest.writeInt(type);
        dest.writeString(targetModeId);
        dest.writeInt(priority);
        dest.writeByte((byte) (enabled ? 1 : 0));
        dest.writeInt(startHour);
        dest.writeInt(startMinute);
        dest.writeInt(endHour);
        dest.writeInt(endMinute);
        dest.writeInt(daysOfWeek);
        dest.writeInt(batteryThreshold);
        dest.writeString(calendarKeyword);
        dest.writeInt(calendarLeadMinutes);
        dest.writeByte((byte) (requireCharging ? 1 : 0));
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<TriggerRule> CREATOR = new Creator<TriggerRule>() {
        @Override public TriggerRule createFromParcel(Parcel in) { return new TriggerRule(in); }
        @Override public TriggerRule[] newArray(int size)        { return new TriggerRule[size]; }
    };
}
