/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.content.Context;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;

import za.co.circleos.sdpkt.LocationContext;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Location-context manager for SDPKT Titanium Protection Engine.
 *
 * Responsibilities:
 *  - Tracks current GPS/network location via android.location.LocationManager
 *  - Matches current location to stored records within MATCH_RADIUS_M (150 m)
 *  - Increments visit counts; promotes Unknown → Known at VISITS_FOR_KNOWN (5)
 *  - Detects HOME context (highest visit count location, visited most recently)
 *  - Detects MOVING context when speed > MOVING_THRESHOLD_MS (8.33 m/s = 30 km/h)
 *  - All data stored locally: /data/circle/sdpkt/locations.json
 *  - Coordinates truncated to 3 decimal places (~110 m precision) for privacy
 *
 * Privacy guarantee: location data is NEVER uploaded or shared.
 */
public class WalletLocationManager implements LocationListener {

    private static final String TAG = "SdpktLocation";

    /* ── Tuning constants ──────────────────────────────────── */
    private static final float  MATCH_RADIUS_M    = 150f;  // metres — snap radius
    private static final int    VISITS_FOR_KNOWN  = 5;     // promotions threshold
    private static final float  MOVING_THRESHOLD_MS = 8.33f; // 30 km/h in m/s
    private static final long   UPDATE_INTERVAL_MS = 30_000L;   // 30 s
    private static final float  UPDATE_MIN_DIST_M  = 50f;       // 50 m
    private static final String LOCATIONS_FILE = "/data/circle/sdpkt/locations.json";

    /* ── State ─────────────────────────────────────────────── */
    private final Context          mContext;
    private final Handler          mWorkerHandler;
    private       Location         mLastLocation;
    private       LocationContext  mCurrentContext;

    // In-memory location records (loaded from disk)
    private final List<LocationRecord> mRecords = new ArrayList<>();
    private final Object               mLock    = new Object();

    public WalletLocationManager(Context ctx, Handler workerHandler) {
        mContext       = ctx;
        mWorkerHandler = workerHandler;
        mCurrentContext = LocationContext.forType(
                LocationContext.TYPE_UNKNOWN, "", 50f);
        load();
    }

    /* ── Lifecycle ─────────────────────────────────────────── */

    /** Register for location updates. Call from PHASE_BOOT_COMPLETED. */
    public void start() {
        try {
            LocationManager lm =
                    (LocationManager) mContext.getSystemService(Context.LOCATION_SERVICE);
            if (lm == null) { Log.w(TAG, "LocationManager unavailable"); return; }

            // Prefer GPS, fall back to network
            if (lm.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                lm.requestLocationUpdates(
                        LocationManager.GPS_PROVIDER,
                        UPDATE_INTERVAL_MS,
                        UPDATE_MIN_DIST_M,
                        this,
                        mWorkerHandler.getLooper());
                Log.i(TAG, "GPS provider registered");
            }
            if (lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
                lm.requestLocationUpdates(
                        LocationManager.NETWORK_PROVIDER,
                        UPDATE_INTERVAL_MS,
                        UPDATE_MIN_DIST_M,
                        this,
                        mWorkerHandler.getLooper());
                Log.i(TAG, "Network provider registered");
            }
        } catch (SecurityException e) {
            Log.w(TAG, "Location permission not available in this context", e);
        } catch (Exception e) {
            Log.e(TAG, "Failed to start location tracking", e);
        }
    }

    public void stop() {
        try {
            LocationManager lm =
                    (LocationManager) mContext.getSystemService(Context.LOCATION_SERVICE);
            if (lm != null) lm.removeUpdates(this);
        } catch (Exception ignored) {}
    }

    /* ── LocationListener ──────────────────────────────────── */

    @Override
    public void onLocationChanged(Location loc) {
        mLastLocation = loc;
        updateContext(loc);
    }

    @Override public void onProviderEnabled(String provider)  {}
    @Override public void onProviderDisabled(String provider) {}
    @Override public void onStatusChanged(String p, int s, Bundle e) {}

    /* ── Context derivation ────────────────────────────────── */

    private void updateContext(Location loc) {
        float speedMs = loc.hasSpeed() ? loc.getSpeed() : 0f;

        // Moving takes priority — regardless of location
        if (speedMs >= MOVING_THRESHOLD_MS) {
            LocationContext c = LocationContext.forType(
                    LocationContext.TYPE_MOVING, "Moving", 90f);
            c.speedMs = speedMs;
            synchronized (mLock) { mCurrentContext = c; }
            Log.d(TAG, "Context: MOVING (" + String.format("%.1f", speedMs * 3.6f) + " km/h)");
            return;
        }

        // Truncate coordinates for stored matching (privacy)
        double lat = Math.round(loc.getLatitude()  * 1000.0) / 1000.0;
        double lon = Math.round(loc.getLongitude() * 1000.0) / 1000.0;

        synchronized (mLock) {
            LocationRecord matched = findNearest(lat, lon, MATCH_RADIUS_M);

            if (matched != null) {
                matched.visitCount++;
                matched.lastVisitMs = System.currentTimeMillis();
                // Promote to KNOWN if threshold reached
                if (matched.contextType == LocationContext.TYPE_UNKNOWN
                        && matched.visitCount >= VISITS_FOR_KNOWN) {
                    matched.contextType = LocationContext.TYPE_KNOWN;
                    Log.i(TAG, "Location promoted to KNOWN: " + matched.label
                            + " (visits=" + matched.visitCount + ")");
                }
                // Detect HOME: highest-visited known location
                maybePromoteHome();
                persist();

                float confidence = Math.min(100f, matched.visitCount * 10f);
                mCurrentContext = LocationContext.forType(
                        matched.contextType, matched.label, confidence);
                mCurrentContext.speedMs = speedMs;
                Log.d(TAG, "Context: " + mCurrentContext.typeName()
                        + " '" + matched.label + "' (visits=" + matched.visitCount + ")");
            } else {
                // New/unseen location
                LocationRecord rec = new LocationRecord();
                rec.lat          = lat;
                rec.lon          = lon;
                rec.label        = "";
                rec.contextType  = LocationContext.TYPE_UNKNOWN;
                rec.visitCount   = 1;
                rec.firstVisitMs = System.currentTimeMillis();
                rec.lastVisitMs  = rec.firstVisitMs;
                mRecords.add(rec);
                persist();

                mCurrentContext = LocationContext.forType(
                        LocationContext.TYPE_UNKNOWN, "", 30f);
                mCurrentContext.speedMs = speedMs;
                Log.d(TAG, "Context: UNKNOWN (new location lat=" + lat + " lon=" + lon + ")");
            }
        }
    }

    /** Promote the most-visited KNOWN location to HOME (if it qualifies). */
    private void maybePromoteHome() {
        LocationRecord bestHome = null;
        for (LocationRecord r : mRecords) {
            if (r.contextType == LocationContext.TYPE_KNOWN
                    || r.contextType == LocationContext.TYPE_HOME) {
                if (bestHome == null || r.visitCount > bestHome.visitCount) {
                    bestHome = r;
                }
            }
        }
        if (bestHome != null && bestHome.visitCount >= VISITS_FOR_KNOWN * 3) {
            // Demote any existing HOME first
            for (LocationRecord r : mRecords) {
                if (r.contextType == LocationContext.TYPE_HOME && r != bestHome) {
                    r.contextType = LocationContext.TYPE_KNOWN;
                }
            }
            if (bestHome.contextType != LocationContext.TYPE_HOME) {
                bestHome.contextType = LocationContext.TYPE_HOME;
                if (bestHome.label.isEmpty()) bestHome.label = "Home";
                Log.i(TAG, "HOME promoted: " + bestHome.label
                        + " visits=" + bestHome.visitCount);
            }
        }
    }

    /* ── Public API ────────────────────────────────────────── */

    /** Return the most recent location context. Never null. */
    public LocationContext getCurrentContext() {
        synchronized (mLock) { return mCurrentContext; }
    }

    /**
     * Label a stored location near the current position.
     * Called from user-facing settings UI (Phase 4).
     */
    public void labelCurrentLocation(String label) {
        if (mLastLocation == null) return;
        double lat = Math.round(mLastLocation.getLatitude()  * 1000.0) / 1000.0;
        double lon = Math.round(mLastLocation.getLongitude() * 1000.0) / 1000.0;
        synchronized (mLock) {
            LocationRecord r = findNearest(lat, lon, MATCH_RADIUS_M);
            if (r != null) {
                r.label = label;
                persist();
                Log.i(TAG, "Location labelled: '" + label + "'");
            }
        }
    }

    /** Mark a location near the current position as risky. */
    public void flagCurrentLocationRisky() {
        if (mLastLocation == null) return;
        double lat = Math.round(mLastLocation.getLatitude()  * 1000.0) / 1000.0;
        double lon = Math.round(mLastLocation.getLongitude() * 1000.0) / 1000.0;
        synchronized (mLock) {
            LocationRecord r = findNearest(lat, lon, MATCH_RADIUS_M * 2);
            if (r != null) {
                r.contextType = LocationContext.TYPE_RISKY;
                persist();
                Log.w(TAG, "Location flagged RISKY: " + lat + "," + lon);
            }
        }
    }

    /* ── Geometry ──────────────────────────────────────────── */

    private LocationRecord findNearest(double lat, double lon, float radiusM) {
        LocationRecord best = null;
        float bestDist = Float.MAX_VALUE;
        for (LocationRecord r : mRecords) {
            float d = distanceM(lat, lon, r.lat, r.lon);
            if (d < radiusM && d < bestDist) {
                bestDist = d;
                best = r;
            }
        }
        return best;
    }

    /** Approximate Euclidean distance in metres (good to ~1% for < 2 km). */
    private float distanceM(double lat1, double lon1, double lat2, double lon2) {
        double dlat = (lat1 - lat2) * 111_000.0;
        double dlon = (lon1 - lon2) * 111_000.0 * Math.cos(Math.toRadians(lat1));
        return (float) Math.sqrt(dlat * dlat + dlon * dlon);
    }

    /* ── Persistence ───────────────────────────────────────── */

    private void persist() {
        try (FileWriter fw = new FileWriter(LOCATIONS_FILE, false)) {
            fw.write("[\n");
            for (int i = 0; i < mRecords.size(); i++) {
                LocationRecord r = mRecords.get(i);
                fw.write(" {\"lat\":" + r.lat + ",\"lon\":" + r.lon
                       + ",\"label\":\"" + esc(r.label) + "\""
                       + ",\"type\":" + r.contextType
                       + ",\"visits\":" + r.visitCount
                       + ",\"first\":" + r.firstVisitMs
                       + ",\"last\":" + r.lastVisitMs + "}");
                if (i < mRecords.size() - 1) fw.write(",");
                fw.write("\n");
            }
            fw.write("]\n");
        } catch (IOException e) {
            Log.e(TAG, "Failed to persist location records", e);
        }
    }

    private void load() {
        File f = new File(LOCATIONS_FILE);
        if (!f.exists()) return;
        try {
            char[] buf = new char[(int) f.length()];
            try (FileReader fr = new FileReader(f)) { fr.read(buf); }
            String json = new String(buf).trim();
            // Minimal JSON array parser
            if (!json.startsWith("[")) return;
            json = json.substring(1, json.length() - 1).trim();
            for (String item : splitObjects(json)) {
                item = item.trim();
                if (item.isEmpty()) continue;
                LocationRecord r = new LocationRecord();
                r.lat          = dbl(item, "lat");
                r.lon          = dbl(item, "lon");
                r.label        = str(item, "label");
                r.contextType  = (int) lng(item, "type");
                r.visitCount   = (int) lng(item, "visits");
                r.firstVisitMs = lng(item, "first");
                r.lastVisitMs  = lng(item, "last");
                mRecords.add(r);
            }
            Log.i(TAG, "Loaded " + mRecords.size() + " location records");
        } catch (Exception e) {
            Log.e(TAG, "Failed to load location records", e);
        }
    }

    /** Split a JSON array body (no nested objects deeper than 1 level). */
    private List<String> splitObjects(String s) {
        List<String> result = new ArrayList<>();
        int depth = 0, start = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{') { if (depth++ == 0) start = i; }
            else if (c == '}') { if (--depth == 0) result.add(s.substring(start, i + 1)); }
        }
        return result;
    }

    private String str(String json, String key) {
        String m = "\"" + key + "\":\"";
        int s = json.indexOf(m); if (s < 0) return "";
        s += m.length(); int e = json.indexOf("\"", s);
        return e > s ? json.substring(s, e) : "";
    }
    private double dbl(String json, String key) {
        String m = "\"" + key + "\":";
        int idx = json.indexOf(m); if (idx < 0) return 0;
        idx += m.length(); int end = idx;
        while (end < json.length() && (Character.isDigit(json.charAt(end))
               || json.charAt(end) == '-' || json.charAt(end) == '.')) end++;
        try { return Double.parseDouble(json.substring(idx, end)); } catch (Exception e) { return 0; }
    }
    private long lng(String json, String key) {
        String m = "\"" + key + "\":";
        int idx = json.indexOf(m); if (idx < 0) return 0;
        idx += m.length(); int end = idx;
        while (end < json.length() && (Character.isDigit(json.charAt(end))
               || json.charAt(end) == '-')) end++;
        try { return Long.parseLong(json.substring(idx, end)); } catch (Exception e) { return 0; }
    }
    private String esc(String s) { return s != null ? s.replace("\"", "\\\"") : ""; }

    /* ── Inner types ───────────────────────────────────────── */

    private static final class LocationRecord {
        double lat, lon;
        String label        = "";
        int    contextType  = LocationContext.TYPE_UNKNOWN;
        int    visitCount   = 0;
        long   firstVisitMs = 0;
        long   lastVisitMs  = 0;
    }
}
