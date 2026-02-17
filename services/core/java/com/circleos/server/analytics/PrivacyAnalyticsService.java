package com.circleos.server.analytics;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.SystemService;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * CircleOS Privacy Analytics Service
 *
 * Aggregates on-device privacy metrics — data never leaves the device:
 * - Permission usage frequency per app
 * - Network connections blocked per day
 * - Threat detections per week
 * - Privacy score trends over time
 *
 * All aggregation is local. Used to power the Privacy Dashboard in CircleSettings.
 */
public class PrivacyAnalyticsService extends SystemService {

    private static final String TAG = "CircleAnalytics";
    private static final String DB_DIR  = "/data/circle/analytics/";
    private static final String DB_NAME = "metrics.db";
    private static final int    DB_VERSION = 1;

    private HandlerThread mHandlerThread;
    private Handler mHandler;
    private AnalyticsDatabase mDb;

    public PrivacyAnalyticsService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        Log.i(TAG, "PrivacyAnalyticsService starting");
        mHandlerThread = new HandlerThread("CircleAnalytics");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());
        publishBinderService("circle.analytics", new AnalyticsImpl());
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            mHandler.post(this::initDatabase);
        }
    }

    private void initDatabase() {
        try {
            new File(DB_DIR).mkdirs();
            mDb = new AnalyticsDatabase(getContext(), DB_DIR + DB_NAME);
            Log.i(TAG, "Analytics database ready");
        } catch (Exception e) {
            Log.e(TAG, "Failed to init analytics database", e);
        }
    }

    /** Record a privacy event for aggregation. Thread-safe — posts to background handler. */
    public void recordEvent(String packageName, String eventType, String detail) {
        if (mHandler == null) return;
        mHandler.post(() -> {
            if (mDb == null) return;
            SQLiteDatabase db = mDb.getWritableDatabase();
            ContentValues cv = new ContentValues();
            cv.put("package_name", packageName);
            cv.put("event_type", eventType);
            cv.put("detail", detail);
            cv.put("timestamp", System.currentTimeMillis());
            db.insert("privacy_events", null, cv);
        });
    }

    /** Returns a privacy score 0-100 for a package. Higher = fewer permissions used. */
    public int getPrivacyScore(String packageName) {
        if (mDb == null) return 50;
        SQLiteDatabase db = mDb.getReadableDatabase();
        Cursor c = db.rawQuery(
            "SELECT COUNT(*) FROM privacy_events WHERE package_name=? AND event_type='PERMISSION_USED'",
            new String[]{packageName}
        );
        int count = 0;
        if (c.moveToFirst()) count = c.getInt(0);
        c.close();
        return Math.max(0, 100 - (count * 5));
    }

    /** Returns aggregate stats for the Privacy Dashboard. */
    public Map<String, Long> getDashboardStats() {
        Map<String, Long> stats = new HashMap<>();
        if (mDb == null) return stats;
        SQLiteDatabase db = mDb.getReadableDatabase();

        long yesterday = System.currentTimeMillis() - 86_400_000L;
        Cursor c = db.rawQuery(
            "SELECT COUNT(*) FROM privacy_events WHERE event_type='NETWORK_BLOCKED' AND timestamp>?",
            new String[]{String.valueOf(yesterday)}
        );
        if (c.moveToFirst()) stats.put("blocked_today", c.getLong(0));
        c.close();

        long lastWeek = System.currentTimeMillis() - 7 * 86_400_000L;
        c = db.rawQuery(
            "SELECT COUNT(*) FROM privacy_events WHERE event_type='THREAT_DETECTED' AND timestamp>?",
            new String[]{String.valueOf(lastWeek)}
        );
        if (c.moveToFirst()) stats.put("threats_week", c.getLong(0));
        c.close();

        return stats;
    }

    private static class AnalyticsDatabase extends SQLiteOpenHelper {
        AnalyticsDatabase(Context context, String path) {
            super(context, path, null, DB_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE IF NOT EXISTS privacy_events (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "package_name TEXT," +
                "event_type TEXT," +
                "detail TEXT," +
                "timestamp INTEGER" +
                ")");
            db.execSQL("CREATE INDEX idx_pkg ON privacy_events(package_name)");
            db.execSQL("CREATE INDEX idx_evt ON privacy_events(event_type, timestamp)");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {}
    }

    private class AnalyticsImpl extends android.os.Binder {}

    public static final class Lifecycle extends SystemService {
        private PrivacyAnalyticsService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new PrivacyAnalyticsService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }
}
