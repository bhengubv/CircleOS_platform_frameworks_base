/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.notification;

import android.app.Notification;
import android.circleos.INotificationPrivacyManager;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.util.Slog;

import com.android.server.SystemService;
import com.circleos.server.privacy.PrivacyLogger;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * CircleOS Notification Privacy Service.
 *
 * Controls which notification content third-party NotificationListenerService
 * implementations can see. Sensitive apps have their notification body replaced
 * with a privacy-preserving placeholder before delivery to listeners.
 *
 * NMS hook point (NotificationManagerService.notifyPostedLocked):
 * <pre>
 *   IBinder binder = ServiceManager.checkService("circle.notification_privacy");
 *   if (binder != null) {
 *       INotificationPrivacyManager npm =
 *               INotificationPrivacyManager.Stub.asInterface(binder);
 *       if (npm.shouldRedactContent(sbn.getPackageName())) {
 *           sbn = redactSbn(sbn); // replace title/text before listener delivery
 *       }
 *   }
 * </pre>
 *
 * Published as "circle.notification_privacy".
 */
public class NotificationPrivacyService extends SystemService {

    private static final String TAG = "CircleNotifPrivacy";

    // ── Database ──────────────────────────────────────────────────────────────

    private static final String DB_PATH  = "/data/circle/privacy/notification_privacy.db";
    private static final int    DB_VER   = 1;
    private static final String T_SENSITIVE = "sensitive_apps";
    private static final String T_BLOCKS    = "listener_blocks";

    private static class NpDbHelper extends SQLiteOpenHelper {
        NpDbHelper(Context ctx) { super(ctx, DB_PATH, null, DB_VER); }

        @Override
        public void onCreate(SQLiteDatabase db) {
            // Apps whose content is redacted from ALL third-party listeners.
            db.execSQL("CREATE TABLE IF NOT EXISTS " + T_SENSITIVE + " (" +
                    "package_name TEXT PRIMARY KEY, added_at INTEGER)");

            // Fine-grained blocks: listener X cannot see notifications from source Y.
            db.execSQL("CREATE TABLE IF NOT EXISTS " + T_BLOCKS + " (" +
                    "listener_package TEXT NOT NULL, " +
                    "source_package TEXT NOT NULL, " +
                    "added_at INTEGER NOT NULL, " +
                    "PRIMARY KEY(listener_package, source_package))");

            // Seed the built-in sensitive apps.
            long now = System.currentTimeMillis();
            for (String pkg : BUILTIN_SENSITIVE) {
                ContentValues cv = new ContentValues(2);
                cv.put("package_name", pkg);
                cv.put("added_at", now);
                db.insertWithOnConflict(T_SENSITIVE, null, cv,
                        SQLiteDatabase.CONFLICT_IGNORE);
            }
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int old, int ver) {}
    }

    /** Apps always treated as sensitive out of the box. */
    private static final String[] BUILTIN_SENSITIVE = {
            "com.android.contacts",
            "com.android.dialer",
            "com.android.messaging",
    };

    // ── Fields ────────────────────────────────────────────────────────────────

    private final HandlerThread mThread;
    private final Handler       mHandler;
    private PrivacyLogger       mLogger;
    private NpDbHelper          mDb;

    // ── Constructor ───────────────────────────────────────────────────────────

    public NotificationPrivacyService(Context context) {
        super(context);
        ensureDataDir();
        mThread = new HandlerThread("CircleNotifPrivacy");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());
    }

    // ── SystemService ─────────────────────────────────────────────────────────

    @Override
    public void onStart() {
        mLogger = new PrivacyLogger(getContext());
        mDb     = new NpDbHelper(getContext());
        publishBinderService("circle.notification_privacy", mBinder);
        Slog.i(TAG, "NotificationPrivacyService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            Slog.i(TAG, "Boot completed — notification privacy active");
        }
    }

    // ── Public API (called from NMS hook) ─────────────────────────────────────

    /**
     * True if notification content from {@code sourcePackage} must be redacted
     * before delivery to any third-party NotificationListenerService.
     *
     * Called from the NMS hook on the NMS thread — must be fast.
     */
    public boolean shouldRedactContent(String sourcePackage) {
        if (sourcePackage == null) return false;
        try {
            SQLiteDatabase db = mDb.getReadableDatabase();
            try (Cursor c = db.query(T_SENSITIVE, new String[]{"package_name"},
                    "package_name=?", new String[]{sourcePackage},
                    null, null, null, "1")) {
                return c.moveToFirst();
            }
        } catch (Exception e) {
            Slog.w(TAG, "shouldRedactContent failed for " + sourcePackage, e);
            return false;
        }
    }

    /**
     * Returns a redacted copy of the notification with all identifiable content
     * replaced by a privacy-preserving placeholder.
     */
    public Notification redactNotification(Notification original, String packageName) {
        mLogger.log(packageName, "NOTIFICATION", "REDACTED", null);
        return new Notification.Builder(getContext(), original)
                .setContentTitle("New message")
                .setContentText("Content hidden for privacy")
                .setTicker(null)
                .build();
    }

    // ── Binder ────────────────────────────────────────────────────────────────

    private final IBinder mBinder = new INotificationPrivacyManager.Stub() {

        @Override
        public boolean shouldRedactContent(String sourcePackage) {
            enforceManagePrivacy();
            return NotificationPrivacyService.this.shouldRedactContent(sourcePackage);
        }

        @Override
        public boolean isListenerBlockedForSource(String listenerPackage,
                String sourcePackage) {
            enforceManagePrivacy();
            if (listenerPackage == null || sourcePackage == null) return false;
            try {
                SQLiteDatabase db = mDb.getReadableDatabase();
                try (Cursor c = db.query(T_BLOCKS, new String[]{"listener_package"},
                        "listener_package=? AND source_package=?",
                        new String[]{listenerPackage, sourcePackage},
                        null, null, null, "1")) {
                    return c.moveToFirst();
                }
            } catch (Exception e) {
                Slog.w(TAG, "isListenerBlockedForSource failed", e);
                return false;
            }
        }

        @Override
        public void addSensitiveApp(String packageName) {
            enforceManagePrivacy();
            mHandler.post(() -> {
                try {
                    ContentValues cv = new ContentValues(2);
                    cv.put("package_name", packageName);
                    cv.put("added_at",     System.currentTimeMillis());
                    mDb.getWritableDatabase().insertWithOnConflict(
                            T_SENSITIVE, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
                    mLogger.log("system", packageName, "NOTIF_SENSITIVE_ADD", null);
                    Slog.i(TAG, "addSensitiveApp: " + packageName);
                } catch (Exception e) {
                    Slog.e(TAG, "addSensitiveApp failed for " + packageName, e);
                }
            });
        }

        @Override
        public void removeSensitiveApp(String packageName) {
            enforceManagePrivacy();
            mHandler.post(() -> {
                try {
                    mDb.getWritableDatabase().delete(T_SENSITIVE,
                            "package_name=?", new String[]{packageName});
                    mLogger.log("system", packageName, "NOTIF_SENSITIVE_REMOVE", null);
                    Slog.i(TAG, "removeSensitiveApp: " + packageName);
                } catch (Exception e) {
                    Slog.e(TAG, "removeSensitiveApp failed for " + packageName, e);
                }
            });
        }

        @Override
        public List<String> getSensitiveApps() {
            enforceManagePrivacy();
            List<String> result = new ArrayList<>();
            try {
                SQLiteDatabase db = mDb.getReadableDatabase();
                try (Cursor c = db.query(T_SENSITIVE, new String[]{"package_name"},
                        null, null, null, null, "package_name")) {
                    while (c.moveToNext()) result.add(c.getString(0));
                }
            } catch (Exception e) {
                Slog.e(TAG, "getSensitiveApps failed", e);
            }
            return result;
        }

        @Override
        public void blockListenerForSource(String listenerPackage, String sourcePackage) {
            enforceManagePrivacy();
            mHandler.post(() -> {
                try {
                    ContentValues cv = new ContentValues(3);
                    cv.put("listener_package", listenerPackage);
                    cv.put("source_package",   sourcePackage);
                    cv.put("added_at",         System.currentTimeMillis());
                    mDb.getWritableDatabase().insertWithOnConflict(
                            T_BLOCKS, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
                    Slog.i(TAG, "blockListenerForSource: " + listenerPackage
                            + " → " + sourcePackage);
                } catch (Exception e) {
                    Slog.e(TAG, "blockListenerForSource failed", e);
                }
            });
        }

        @Override
        public void unblockListenerForSource(String listenerPackage, String sourcePackage) {
            enforceManagePrivacy();
            mHandler.post(() -> {
                try {
                    mDb.getWritableDatabase().delete(T_BLOCKS,
                            "listener_package=? AND source_package=?",
                            new String[]{listenerPackage, sourcePackage});
                    Slog.i(TAG, "unblockListenerForSource: " + listenerPackage
                            + " → " + sourcePackage);
                } catch (Exception e) {
                    Slog.e(TAG, "unblockListenerForSource failed", e);
                }
            });
        }
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void enforceManagePrivacy() {
        getContext().enforceCallingOrSelfPermission(
                "com.circleos.permission.MANAGE_PRIVACY",
                "Requires com.circleos.permission.MANAGE_PRIVACY");
    }

    private static void ensureDataDir() {
        for (String path : new String[]{"/data/circle", "/data/circle/privacy"}) {
            File dir = new File(path);
            if (!dir.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
        }
    }

    // ── Lifecycle wrapper ─────────────────────────────────────────────────────

    public static final class Lifecycle extends SystemService {
        private NotificationPrivacyService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new NotificationPrivacyService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            if (mService != null) mService.onBootPhase(phase);
        }
    }
}
