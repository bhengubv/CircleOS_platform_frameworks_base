/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.security.AttackCampaign;
import za.co.circleos.security.DmzAnalysisResult;
import za.co.circleos.security.IDataAcuityResearcherApi;
import za.co.circleos.security.IocBundle;
import za.co.circleos.security.QuarantineRecord;
import za.co.circleos.security.ThreatIndicator;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Data Acuity Researcher API Service — Phase 3.
 *
 * Aggregates output from IocExtractor, CampaignCorrelator, and InfrastructureMapper
 * to provide a complete threat intelligence API for authorized researchers.
 *
 * Service name: "circle.researcher_api"
 *
 * Authorization: requires RESEARCHER_API permission (signature|privileged).
 * In production: subscription tier checked via Data Acuity API token.
 *
 * STIX 2.1 output: IocBundle.stixJson contains a complete STIX 2.1 Bundle JSON.
 *
 * Webhook / WebSocket (Phase 4): real-time IOC push to subscribed researchers.
 */
public class ResearcherApiService extends SystemService {

    private static final String TAG          = "CircleResearcherApi";
    public  static final String SERVICE_NAME = "circle.researcher_api";
    public  static final int    VERSION      = 1;

    // ── SQLite IOC store ──────────────────────────────────────────────────

    private static final String DB_PATH = "/data/circle/security/ioc_store.db";
    private static final int    DB_VER  = 1;
    private static final String T_IOCS  = "threat_indicators";

    private static class IocDbHelper extends SQLiteOpenHelper {
        IocDbHelper(Context ctx) {
            super(ctx, DB_PATH, null, DB_VER);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE IF NOT EXISTS " + T_IOCS + " ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "type INTEGER NOT NULL, "
                    + "value TEXT NOT NULL, "
                    + "confidence INTEGER NOT NULL, "
                    + "source TEXT, "
                    + "first_seen INTEGER NOT NULL, "
                    + "last_seen INTEGER NOT NULL, "
                    + "description TEXT, "
                    + "UNIQUE(type, value) ON CONFLICT REPLACE)");
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_iocs_first_seen ON "
                    + T_IOCS + "(first_seen)");
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_iocs_value ON "
                    + T_IOCS + "(value)");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {}
    }

    private final BinderService     mBinderService    = new BinderService();
    private IocExtractor            mIocExtractor;
    private CampaignCorrelator      mCorrelator;
    private InfrastructureMapper    mMapper;
    private HandlerThread           mWorkerThread;
    private android.os.Handler      mWorkerHandler;
    private IocDbHelper             mIocDb;

    /* ── Lifecycle ────────────────────────────────────────────────────── */

    public static class Lifecycle extends SystemService {
        private ResearcherApiService mService;

        public Lifecycle(Context ctx) { super(ctx); }

        @Override
        public void onStart() {
            mService = new ResearcherApiService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }

    public ResearcherApiService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        new File("/data/circle/security").mkdirs();
        mIocDb = new IocDbHelper(getContext());
        publishBinderService(SERVICE_NAME, mBinderService);
        Log.i(TAG, "ResearcherApiService started (IOC DB: " + DB_PATH + ")");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            mWorkerThread  = new HandlerThread("ResearcherApi");
            mWorkerThread.start();
            mWorkerHandler = new android.os.Handler(mWorkerThread.getLooper());
            mIocExtractor  = new IocExtractor();
            mCorrelator    = new CampaignCorrelator();
            mMapper        = new InfrastructureMapper();
            Log.i(TAG, "ResearcherApiService boot-complete init done, IOC count="
                    + dbCountIocs());
        }
    }

    /* ── Public API (called from CircleFileDmzService + QuarantineManager) ── */

    /** Called when a DMZ analysis completes — extract and correlate IOCs. */
    public void processDmzResult(DmzAnalysisResult result) {
        if (mWorkerHandler == null) return;
        mWorkerHandler.post(() -> {
            List<ThreatIndicator> iocs = mIocExtractor.extractFromDmzResult(result);
            dbInsertIocs(iocs);
            List<String> campaigns = mCorrelator.correlate(iocs);
            mMapper.ingestCampaigns(mCorrelator.getAllCampaigns());
            Log.i(TAG, "Processed DMZ result → " + iocs.size() + " IOCs, "
                    + campaigns.size() + " campaigns");
        });
    }

    /** Called when a file is quarantined. */
    public void processQuarantineRecord(QuarantineRecord record) {
        if (mWorkerHandler == null) return;
        mWorkerHandler.post(() -> {
            List<ThreatIndicator> iocs = mIocExtractor.extractFromQuarantine(record);
            dbInsertIocs(iocs);
            mCorrelator.correlate(iocs);
            mMapper.ingestCampaigns(mCorrelator.getAllCampaigns());
        });
    }

    /* ── Binder ───────────────────────────────────────────────────────── */

    private final class BinderService extends IDataAcuityResearcherApi.Stub {

        @Override
        public List<AttackCampaign> listCampaigns(int maxResults) {
            List<AttackCampaign> all = mCorrelator.getAllCampaigns();
            if (maxResults > 0 && all.size() > maxResults) {
                return all.subList(0, maxResults);
            }
            return all;
        }

        @Override
        public AttackCampaign getCampaign(String campaignId) {
            return mCorrelator.getCampaign(campaignId);
        }

        @Override
        public IocBundle getIocBundle(String campaignId) {
            AttackCampaign c = mCorrelator.getCampaign(campaignId);
            if (c == null) return null;
            // Fetch IOCs whose value is in the campaign's IOC set.
            List<ThreatIndicator> campaignIocs = new ArrayList<>();
            for (String iocValue : c.iocs) {
                List<ThreatIndicator> matched = dbQueryByValue(iocValue);
                campaignIocs.addAll(matched);
            }
            return buildStixBundle(campaignIocs, 1);
        }

        @Override
        public IocBundle getAllIocs(long sinceEpochMs, int maxResults) {
            List<ThreatIndicator> filtered = dbQuerySince(sinceEpochMs, maxResults);
            return buildStixBundle(filtered, mCorrelator.getAllCampaigns().size());
        }

        @Override
        public IocBundle pollNewIocs(long sinceEpochMs) {
            return getAllIocs(sinceEpochMs, 0);
        }

        @Override
        public List<String> getRelatedInfrastructure(String ipOrDomain) {
            return mMapper.getRelated(ipOrDomain);
        }

        @Override
        public List<String> predictRelatedInfrastructure(String campaignId) {
            return mMapper.predictRelated(campaignId);
        }

        @Override
        public int getTotalCampaigns() {
            return mCorrelator.getAllCampaigns().size();
        }

        @Override
        public int getTotalIocs() {
            return dbCountIocs();
        }

        @Override
        public int getServiceVersion() { return VERSION; }
    }

    /* ── SQLite IOC helpers ───────────────────────────────────────────── */

    /** Insert a list of ThreatIndicators. Uses CONFLICT REPLACE on (type, value). */
    private void dbInsertIocs(List<ThreatIndicator> iocs) {
        if (iocs == null || iocs.isEmpty()) return;
        try {
            SQLiteDatabase db = mIocDb.getWritableDatabase();
            db.beginTransaction();
            try {
                for (ThreatIndicator ti : iocs) {
                    ContentValues cv = new ContentValues(7);
                    cv.put("type",        ti.type);
                    cv.put("value",       ti.value);
                    cv.put("confidence",  ti.confidence);
                    cv.put("source",      ti.source);
                    cv.put("first_seen",  ti.firstSeen);
                    cv.put("last_seen",   ti.lastSeen);
                    cv.put("description", ti.description);
                    db.insertWithOnConflict(T_IOCS, null, cv,
                            SQLiteDatabase.CONFLICT_REPLACE);
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } catch (Exception e) {
            Log.e(TAG, "dbInsertIocs failed", e);
        }
    }

    /** Query IOCs with first_seen >= sinceEpochMs, optionally capped to maxResults. */
    private List<ThreatIndicator> dbQuerySince(long sinceEpochMs, int maxResults) {
        List<ThreatIndicator> result = new ArrayList<>();
        try {
            SQLiteDatabase db = mIocDb.getReadableDatabase();
            String limit = maxResults > 0 ? String.valueOf(maxResults) : null;
            try (Cursor c = db.query(T_IOCS, null,
                    "first_seen >= ?", new String[]{String.valueOf(sinceEpochMs)},
                    null, null, "first_seen ASC", limit)) {
                while (c.moveToNext()) result.add(cursorToThreatIndicator(c));
            }
        } catch (Exception e) {
            Log.e(TAG, "dbQuerySince failed", e);
        }
        return result;
    }

    /** Query IOCs matching a specific value (exact match). */
    private List<ThreatIndicator> dbQueryByValue(String value) {
        List<ThreatIndicator> result = new ArrayList<>();
        try {
            SQLiteDatabase db = mIocDb.getReadableDatabase();
            try (Cursor c = db.query(T_IOCS, null,
                    "value=?", new String[]{value},
                    null, null, null, null)) {
                while (c.moveToNext()) result.add(cursorToThreatIndicator(c));
            }
        } catch (Exception e) {
            Log.e(TAG, "dbQueryByValue failed for " + value, e);
        }
        return result;
    }

    /** Returns total row count in the IOC table. */
    private int dbCountIocs() {
        try {
            SQLiteDatabase db = mIocDb.getReadableDatabase();
            try (Cursor c = db.rawQuery("SELECT COUNT(*) FROM " + T_IOCS, null)) {
                return c.moveToFirst() ? c.getInt(0) : 0;
            }
        } catch (Exception e) {
            Log.w(TAG, "dbCountIocs failed", e);
            return 0;
        }
    }

    private static ThreatIndicator cursorToThreatIndicator(Cursor c) {
        ThreatIndicator ti = new ThreatIndicator();
        ti.type        = c.getInt(c.getColumnIndexOrThrow("type"));
        ti.value       = c.getString(c.getColumnIndexOrThrow("value"));
        ti.confidence  = c.getInt(c.getColumnIndexOrThrow("confidence"));
        ti.source      = c.getString(c.getColumnIndexOrThrow("source"));
        ti.firstSeen   = c.getLong(c.getColumnIndexOrThrow("first_seen"));
        ti.lastSeen    = c.getLong(c.getColumnIndexOrThrow("last_seen"));
        ti.description = c.getString(c.getColumnIndexOrThrow("description"));
        return ti;
    }

    /* ── STIX 2.1 bundle builder ──────────────────────────────────────── */

    private IocBundle buildStixBundle(List<ThreatIndicator> iocs, int campaignCount) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"type\":\"bundle\",\"id\":\"bundle--")
          .append(UUID.randomUUID())
          .append("\",\"spec_version\":\"2.1\",\"objects\":[");

        for (int i = 0; i < iocs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(mIocExtractor.toStixIndicator(iocs.get(i)));
        }
        sb.append("]}");

        IocBundle bundle = new IocBundle();
        bundle.bundleId      = UUID.randomUUID().toString();
        bundle.stixJson      = sb.toString();
        bundle.generatedAtMs = System.currentTimeMillis();
        bundle.iocCount      = iocs.size();
        bundle.campaignCount = campaignCount;
        if (!iocs.isEmpty()) {
            bundle.oldestIocMs = iocs.stream().mapToLong(t -> t.firstSeen).min().orElse(0);
            bundle.newestIocMs = iocs.stream().mapToLong(t -> t.lastSeen).max().orElse(0);
        }
        return bundle;
    }
}
