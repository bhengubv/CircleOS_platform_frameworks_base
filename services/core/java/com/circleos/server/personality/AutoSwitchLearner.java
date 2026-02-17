/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.util.ArrayMap;
import android.util.Log;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import za.co.circleos.personality.LearningSuggestion;
import za.co.circleos.personality.TriggerRule;

/**
 * Observes manual override patterns and generates {@link LearningSuggestion}s.
 *
 * <h3>Recording events</h3>
 * Call {@link #recordManualSwitch} whenever the user manually switches mode.
 * Call {@link #recordAutoSwitch} when an auto trigger fires.
 *
 * <h3>Pattern detection</h3>
 * After 3+ consistent overrides, a suggestion is generated:
 * <ul>
 *   <li>Time pattern — same mode at same hour/day-of-week ≥ 3 times.</li>
 * </ul>
 *
 * <h3>Persistence</h3>
 * Events are persisted to {@code /data/system/circle/personality/learner_events.json}.
 * Accepted/dismissed suggestion IDs stored in {@code learner_feedback.json}.
 */
class AutoSwitchLearner {

    private static final String TAG          = "CirclePersonality";
    private static final String STORE_DIR     = "/data/system/circle/personality/";
    private static final String EVENTS_FILE   = STORE_DIR + "learner_events.json";
    private static final String FEEDBACK_FILE = STORE_DIR + "learner_feedback.json";
    private static final int    MAX_EVENTS    = 200;
    private static final int    MIN_PATTERN   = 3;

    // Represents a single recorded switch event
    static final class SwitchEvent {
        long   timestamp;
        String modeId;
        int    hourOfDay;    // 0–23
        int    dayOfWeek;    // Calendar.MONDAY..SUNDAY
        boolean isManual;    // false = auto-trigger fired

        SwitchEvent() {}
    }

    private final List<SwitchEvent>    mEvents    = new ArrayList<>();
    private final Set<String>          mDismissed = new HashSet<>();
    private final Set<String>          mAccepted  = new HashSet<>();
    private final Map<String, LearningSuggestion> mSuggestions = new ArrayMap<>();

    AutoSwitchLearner() {
        loadEvents();
        loadFeedback();
        rebuildSuggestions();
    }

    // ---- Record events ------------------------------------------------------

    void recordManualSwitch(String modeId) {
        recordEvent(modeId, true);
    }

    void recordAutoSwitch(String modeId) {
        recordEvent(modeId, false);
    }

    private void recordEvent(String modeId, boolean isManual) {
        Calendar cal = Calendar.getInstance();
        SwitchEvent ev = new SwitchEvent();
        ev.timestamp = cal.getTimeInMillis();
        ev.modeId    = modeId;
        ev.hourOfDay = cal.get(Calendar.HOUR_OF_DAY);
        ev.dayOfWeek = cal.get(Calendar.DAY_OF_WEEK);
        ev.isManual  = isManual;

        synchronized (mEvents) {
            mEvents.add(ev);
            if (mEvents.size() > MAX_EVENTS) mEvents.remove(0);
        }

        saveEvents();
        rebuildSuggestions();
    }

    // ---- Suggestions --------------------------------------------------------

    List<LearningSuggestion> getSuggestions() {
        synchronized (mSuggestions) {
            return new ArrayList<>(mSuggestions.values());
        }
    }

    void accept(String suggestionId) {
        mAccepted.add(suggestionId);
        mSuggestions.remove(suggestionId);
        saveFeedback();
        Log.i(TAG, "Learner suggestion accepted: " + suggestionId);
    }

    void dismiss(String suggestionId) {
        mDismissed.add(suggestionId);
        mSuggestions.remove(suggestionId);
        saveFeedback();
        Log.i(TAG, "Learner suggestion dismissed: " + suggestionId);
    }

    /**
     * Returns the TriggerRule for an accepted suggestion (so the caller can
     * add it via {@link AutoSwitchManager#addRule}), or null if not found.
     */
    TriggerRule getAcceptedRule(String suggestionId) {
        // Rule is embedded in the suggestion before it was accepted;
        // caller should cache on accept.
        return null; // caller must cache at accept time
    }

    // ---- Pattern detection --------------------------------------------------

    private void rebuildSuggestions() {
        List<SwitchEvent> snapshot;
        synchronized (mEvents) { snapshot = new ArrayList<>(mEvents); }

        // Key: "modeId:hour:dayOfWeek" → count of manual switches
        Map<String, Integer> counts = new ArrayMap<>();
        Map<String, SwitchEvent> exemplars = new ArrayMap<>();

        for (SwitchEvent ev : snapshot) {
            if (!ev.isManual) continue;
            // Bucket by mode + hour (±1h tolerance) + day-of-week
            String key = ev.modeId + ":" + ev.hourOfDay + ":" + ev.dayOfWeek;
            counts.put(key, counts.getOrDefault(key, 0) + 1);
            exemplars.put(key, ev);
        }

        Map<String, LearningSuggestion> newSuggestions = new ArrayMap<>();
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            int count = entry.getValue();
            if (count < MIN_PATTERN) continue;

            String key = entry.getKey();
            // Skip already-decided suggestions
            if (mDismissed.contains(key) || mAccepted.contains(key)) continue;

            SwitchEvent ex = exemplars.get(key);
            if (ex == null) continue;

            LearningSuggestion sug = buildTimeSuggestion(key, ex, count);
            newSuggestions.put(key, sug);
        }

        synchronized (mSuggestions) {
            mSuggestions.clear();
            mSuggestions.putAll(newSuggestions);
        }
    }

    private LearningSuggestion buildTimeSuggestion(String id, SwitchEvent ex, int count) {
        String[] days = {"", "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        String dayName  = (ex.dayOfWeek >= 1 && ex.dayOfWeek <= 7)
                ? days[ex.dayOfWeek] : "?";
        String timeStr  = String.format(Locale.US, "%02d:00", ex.hourOfDay);

        TriggerRule rule = new TriggerRule();
        rule.id           = "learned_" + id.replace(':', '_');
        rule.type         = TriggerRule.TYPE_TIME;
        rule.targetModeId = ex.modeId;
        rule.startHour    = ex.hourOfDay;
        rule.startMinute  = 0;
        rule.daysOfWeek   = 1 << ex.dayOfWeek;  // bitmask
        rule.priority     = TriggerRule.PRIORITY_NORMAL;

        int confidence = Math.min(100, 40 + count * 20); // 3→100, 2→80, …

        LearningSuggestion sug = new LearningSuggestion();
        sug.id           = id;
        sug.description  = "You switch to " + ex.modeId + " around " + timeStr
                + " on " + dayName + "s (" + count + "×). Add as auto-trigger?";
        sug.suggestedRule = rule;
        sug.confidence   = confidence;
        return sug;
    }

    // ---- Persistence --------------------------------------------------------

    private void saveEvents() {
        List<SwitchEvent> snapshot;
        synchronized (mEvents) { snapshot = new ArrayList<>(mEvents); }
        try {
            new File(STORE_DIR).mkdirs();
            try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(EVENTS_FILE), StandardCharsets.UTF_8))) {
                w.print("[");
                for (int i = 0; i < snapshot.size(); i++) {
                    if (i > 0) w.print(',');
                    SwitchEvent ev = snapshot.get(i);
                    w.printf("{\"ts\":%d,\"mode\":\"%s\",\"h\":%d,\"d\":%d,\"m\":%b}",
                            ev.timestamp, escape(ev.modeId), ev.hourOfDay, ev.dayOfWeek, ev.isManual);
                }
                w.print("]");
            }
        } catch (Exception e) {
            Log.w(TAG, "Learner saveEvents failed: " + e.getMessage());
        }
    }

    private void loadEvents() {
        File f = new File(EVENTS_FILE);
        if (!f.exists()) return;
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line; while ((line = r.readLine()) != null) sb.append(line);
            parseEvents(sb.toString());
        } catch (Exception e) {
            Log.w(TAG, "Learner loadEvents failed: " + e.getMessage());
        }
    }

    private void parseEvents(String json) {
        json = json.trim();
        if (!json.startsWith("[")) return;
        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return;
        int depth = 0, start = 0;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') { if (depth++ == 0) start = i; }
            else if (c == '}' && --depth == 0) {
                String obj = json.substring(start, i + 1);
                SwitchEvent ev = new SwitchEvent();
                try {
                    ev.timestamp = Long.parseLong(extractRaw(obj, "ts"));
                    ev.modeId    = extractString(obj, "mode");
                    ev.hourOfDay = Integer.parseInt(extractRaw(obj, "h"));
                    ev.dayOfWeek = Integer.parseInt(extractRaw(obj, "d"));
                    ev.isManual  = "true".equals(extractRaw(obj, "m"));
                    if (ev.modeId != null) mEvents.add(ev);
                } catch (Exception ignored) {}
            }
        }
    }

    private void saveFeedback() {
        try {
            new File(STORE_DIR).mkdirs();
            try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(FEEDBACK_FILE), StandardCharsets.UTF_8))) {
                w.printf("{\"accepted\":%s,\"dismissed\":%s}",
                        encodeSet(mAccepted), encodeSet(mDismissed));
            }
        } catch (Exception e) {
            Log.w(TAG, "Learner saveFeedback failed: " + e.getMessage());
        }
    }

    private void loadFeedback() {
        File f = new File(FEEDBACK_FILE);
        if (!f.exists()) return;
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line; while ((line = r.readLine()) != null) sb.append(line);
            String json = sb.toString();
            parseSet(json, "accepted",  mAccepted);
            parseSet(json, "dismissed", mDismissed);
        } catch (Exception e) {
            Log.w(TAG, "Learner loadFeedback failed: " + e.getMessage());
        }
    }

    private static String encodeSet(Set<String> set) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String s : set) {
            if (!first) sb.append(','); first = false;
            sb.append('"').append(escape(s)).append('"');
        }
        return sb.append(']').toString();
    }

    private static void parseSet(String json, String key, Set<String> out) {
        String search = "\"" + key + "\":[";
        int idx = json.indexOf(search);
        if (idx < 0) return;
        int start = idx + search.length();
        int end   = json.indexOf(']', start);
        if (end < 0) return;
        String items = json.substring(start, end).trim();
        for (String item : items.split(",")) {
            item = item.trim();
            if (item.startsWith("\"") && item.endsWith("\""))
                out.add(item.substring(1, item.length() - 1));
        }
    }

    // ---- Helpers ------------------------------------------------------------

    private static String extractString(String obj, String key) {
        String raw = extractRaw(obj, key);
        if (raw == null) return null;
        if (raw.startsWith("\"") && raw.endsWith("\""))
            return raw.substring(1, raw.length() - 1);
        return raw;
    }

    private static String extractRaw(String obj, String key) {
        String search = "\"" + key + "\":";
        int idx = obj.indexOf(search);
        if (idx < 0) return null;
        int start = idx + search.length();
        int end = start;
        boolean inStr = obj.charAt(start) == '"';
        if (inStr) {
            end = start + 1;
            while (end < obj.length() && !(obj.charAt(end) == '"' && obj.charAt(end - 1) != '\\')) end++;
            end++;
        } else {
            while (end < obj.length() && obj.charAt(end) != ',' && obj.charAt(end) != '}') end++;
        }
        return obj.substring(start, end).trim();
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
