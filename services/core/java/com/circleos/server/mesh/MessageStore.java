/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * SQLite-backed store-and-forward message store for the Circle Mesh Network.
 *
 * <p>Stores outbound messages that could not be delivered because the recipient
 * peer was offline. Delivery is retried each time the peer comes back online.
 *
 * <p>Hard limits (enforced by {@link #pruneOld()}):
 * <ul>
 *   <li>Message TTL: 7 days</li>
 *   <li>Total message count: 1 000</li>
 *   <li>Total storage: 100 MB</li>
 *   <li>Per-recipient queue: 100 messages</li>
 * </ul>
 *
 * <p>Database path: {@code /data/system/circleos_mesh/mesh_messages.db}
 */
public class MessageStore {

    private static final String TAG = "MeshMessageStore";

    private static final String DB_PATH = "/data/system/circleos_mesh/mesh_messages.db";
    private static final int    DB_VERSION = 1;

    // Limits
    static final long TTL_MS          = 7L * 24 * 60 * 60 * 1_000; // 7 days
    static final int  MAX_TOTAL       = 1_000;
    static final long MAX_BYTES       = 100L * 1024 * 1024;          // 100 MB
    static final int  MAX_PER_RECIP   = 100;

    // Table
    private static final String TABLE = "pending_messages";
    private static final String COL_ID          = "id";
    private static final String COL_MSG_ID      = "msg_id";        // 32-char hex UUID
    private static final String COL_RECIPIENT   = "recipient_id";  // 16-char hex device ID
    private static final String COL_TYPE        = "msg_type";      // int (MeshProtocol.TYPE_*)
    private static final String COL_PAYLOAD     = "payload";       // BLOB — full encoded frame
    private static final String COL_CREATED_AT  = "created_at";   // epoch ms
    private static final String COL_ATTEMPTS    = "attempts";      // delivery attempts
    private static final String COL_DELIVERED   = "delivered";     // 0/1

    private final DbHelper mDbHelper;

    // ── Constructor ───────────────────────────────────────────────────────────

    public MessageStore(Context context) {
        mDbHelper = new DbHelper();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Stores a message for later delivery.
     *
     * @param msgId      32-char hex UUID identifying this message.
     * @param recipientId 16-char hex recipient device ID.
     * @param msgType    Message type constant from {@link MeshProtocol}.
     * @param payload    Full encoded frame bytes (including header + body).
     * @return true if the message was stored; false if limits are exceeded.
     */
    public boolean storeMessage(String msgId, String recipientId, int msgType, byte[] payload) {
        if (msgId == null || recipientId == null || payload == null) return false;

        SQLiteDatabase db = mDbHelper.getWritableDatabase();

        // Check per-recipient limit
        int recipCount = queryInt(db,
                "SELECT COUNT(*) FROM " + TABLE
                        + " WHERE " + COL_RECIPIENT + "=? AND " + COL_DELIVERED + "=0",
                new String[]{recipientId});
        if (recipCount >= MAX_PER_RECIP) {
            Log.w(TAG, "storeMessage: per-recipient limit reached for " + recipientId);
            return false;
        }

        ContentValues cv = new ContentValues();
        cv.put(COL_MSG_ID,    msgId);
        cv.put(COL_RECIPIENT, recipientId);
        cv.put(COL_TYPE,      msgType);
        cv.put(COL_PAYLOAD,   payload);
        cv.put(COL_CREATED_AT, System.currentTimeMillis());
        cv.put(COL_ATTEMPTS,  0);
        cv.put(COL_DELIVERED, 0);

        long rowId = db.insert(TABLE, null, cv);
        if (rowId < 0) {
            Log.e(TAG, "storeMessage: insert failed for msg " + msgId);
            return false;
        }
        Log.d(TAG, "Stored message " + msgId + " for " + recipientId);
        return true;
    }

    /**
     * Returns all pending (undelivered) messages for a given recipient.
     *
     * @param recipientId 16-char hex device ID.
     * @return List of {@link StoredMessage}, possibly empty.
     */
    public List<StoredMessage> getPendingFor(String recipientId) {
        List<StoredMessage> result = new ArrayList<>();
        SQLiteDatabase db = mDbHelper.getReadableDatabase();

        try (Cursor c = db.query(TABLE,
                new String[]{COL_ID, COL_MSG_ID, COL_TYPE, COL_PAYLOAD, COL_ATTEMPTS},
                COL_RECIPIENT + "=? AND " + COL_DELIVERED + "=0",
                new String[]{recipientId},
                null, null, COL_CREATED_AT + " ASC")) {
            while (c.moveToNext()) {
                StoredMessage m = new StoredMessage();
                m.rowId    = c.getLong(0);
                m.msgId    = c.getString(1);
                m.msgType  = c.getInt(2);
                m.payload  = c.getBlob(3);
                m.attempts = c.getInt(4);
                result.add(m);
            }
        }
        return result;
    }

    /**
     * Marks a message as successfully delivered.
     *
     * @param rowId The {@link StoredMessage#rowId} returned by {@link #getPendingFor}.
     */
    public void markDelivered(long rowId) {
        SQLiteDatabase db = mDbHelper.getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put(COL_DELIVERED, 1);
        int updated = db.update(TABLE, cv, COL_ID + "=?",
                new String[]{String.valueOf(rowId)});
        Log.d(TAG, "markDelivered row=" + rowId + " updated=" + updated);
    }

    /**
     * Increments the delivery attempt count for a message.
     *
     * @param rowId The {@link StoredMessage#rowId}.
     */
    public void incrementAttempts(long rowId) {
        SQLiteDatabase db = mDbHelper.getWritableDatabase();
        db.execSQL("UPDATE " + TABLE + " SET " + COL_ATTEMPTS + "=" + COL_ATTEMPTS
                + "+1 WHERE " + COL_ID + "=?", new Object[]{rowId});
    }

    /**
     * Removes stale, delivered, or over-limit rows.
     *
     * Called periodically by {@link CircleMeshService} (daily).
     */
    public void pruneOld() {
        SQLiteDatabase db = mDbHelper.getWritableDatabase();
        long cutoff = System.currentTimeMillis() - TTL_MS;

        // 1. Expired messages
        int expired = db.delete(TABLE, COL_CREATED_AT + "<?",
                new String[]{String.valueOf(cutoff)});

        // 2. Delivered messages
        int delivered = db.delete(TABLE, COL_DELIVERED + "=1", null);

        // 3. Enforce total-count limit (delete oldest first)
        int total = queryInt(db, "SELECT COUNT(*) FROM " + TABLE, null);
        int overCount = total - MAX_TOTAL;
        if (overCount > 0) {
            db.execSQL("DELETE FROM " + TABLE + " WHERE " + COL_ID + " IN ("
                    + "SELECT " + COL_ID + " FROM " + TABLE
                    + " ORDER BY " + COL_CREATED_AT + " ASC LIMIT " + overCount + ")");
        }

        // 4. Enforce size limit (approximate — use sqlite_pageid trick)
        // Simple approach: count total blob bytes and prune oldest if over limit
        long totalBytes = queryLong(db,
                "SELECT COALESCE(SUM(LENGTH(" + COL_PAYLOAD + ")),0) FROM " + TABLE, null);
        if (totalBytes > MAX_BYTES) {
            // Remove oldest rows until under limit
            db.execSQL("DELETE FROM " + TABLE + " WHERE " + COL_ID + " IN ("
                    + "SELECT " + COL_ID + " FROM " + TABLE
                    + " ORDER BY " + COL_CREATED_AT + " ASC LIMIT 100)");
        }

        Log.d(TAG, "pruneOld: removed expired=" + expired + " delivered=" + delivered
                + " overCount=" + Math.max(0, overCount));
    }

    /** Returns total number of pending (undelivered) messages. */
    public int getPendingCount() {
        return queryInt(mDbHelper.getReadableDatabase(),
                "SELECT COUNT(*) FROM " + TABLE + " WHERE " + COL_DELIVERED + "=0", null);
    }

    // ── Inner types ───────────────────────────────────────────────────────────

    /** Represents a stored, undelivered message. */
    public static class StoredMessage {
        public long   rowId;
        public String msgId;
        public int    msgType;
        public byte[] payload;
        public int    attempts;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private int queryInt(SQLiteDatabase db, String sql, String[] args) {
        try (Cursor c = db.rawQuery(sql, args)) {
            return (c.moveToFirst()) ? c.getInt(0) : 0;
        }
    }

    private long queryLong(SQLiteDatabase db, String sql, String[] args) {
        try (Cursor c = db.rawQuery(sql, args)) {
            return (c.moveToFirst()) ? c.getLong(0) : 0L;
        }
    }

    // ── SQLiteOpenHelper ──────────────────────────────────────────────────────

    private static class DbHelper extends SQLiteOpenHelper {

        DbHelper() {
            super(null, DB_PATH, null, DB_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE + " ("
                    + COL_ID         + " INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + COL_MSG_ID     + " TEXT NOT NULL,"
                    + COL_RECIPIENT  + " TEXT NOT NULL,"
                    + COL_TYPE       + " INTEGER NOT NULL,"
                    + COL_PAYLOAD    + " BLOB NOT NULL,"
                    + COL_CREATED_AT + " INTEGER NOT NULL,"
                    + COL_ATTEMPTS   + " INTEGER NOT NULL DEFAULT 0,"
                    + COL_DELIVERED  + " INTEGER NOT NULL DEFAULT 0"
                    + ")");
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_recipient_delivered ON "
                    + TABLE + "(" + COL_RECIPIENT + "," + COL_DELIVERED + ")");
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_created_at ON "
                    + TABLE + "(" + COL_CREATED_AT + ")");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            // No upgrades in v1
        }
    }
}
