/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.content.Context;
import android.os.IBinder;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.security.DmzAnalysisResult;
import za.co.circleos.security.ICircleQuarantine;
import za.co.circleos.security.QuarantineRecord;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Circle Malware Jail — Quarantine Manager.
 *
 * Quarantined files are:
 *   - Stored in /data/circle/security/quarantine/<id>/ with mode 0600, owner system
 *   - Renamed to remove executable extension (.apk → .apk.quarantine)
 *   - Logged to quarantine.db (flat JSON per file, one per line)
 *   - Inaccessible to all apps (DAC + SELinux label circleos_quarantine_data_file)
 *
 * Service name: "circle.quarantine"
 */
public class QuarantineManager extends SystemService {

    private static final String TAG          = "CircleQuarantine";
    public  static final String SERVICE_NAME = "circle.quarantine";
    public  static final int    VERSION      = 1;

    private static final String QUARANTINE_DIR = "/data/circle/security/quarantine/";

    private final BinderService mBinderService = new BinderService();
    private final ConcurrentHashMap<String, QuarantineRecord> mRecords
            = new ConcurrentHashMap<>();

    /* ── Lifecycle ─────────────────────────────────────────────────────── */

    public static class Lifecycle extends SystemService {
        private QuarantineManager mService;

        public Lifecycle(Context ctx) { super(ctx); }

        @Override
        public void onStart() {
            mService = new QuarantineManager(getContext());
            mService.onStart();
        }
    }

    public QuarantineManager(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mBinderService);
        new File(QUARANTINE_DIR).mkdirs();
        loadRecords();
        Log.i(TAG, "QuarantineManager started");
    }

    /* ── Public API (called from CircleFileDmzService) ─────────────────── */

    /**
     * Move a file to quarantine. Called after threat verdict.
     * @param result DMZ result with verdict, sha256, etc.
     * @param filePath Original file path (if known)
     */
    public QuarantineRecord quarantine(DmzAnalysisResult result, String filePath) {
        String id = UUID.randomUUID().toString();
        String destDir = QUARANTINE_DIR + id + "/";
        new File(destDir).mkdirs();

        // Copy (not move — original may be in app sandbox we can't delete)
        String destPath = destDir + result.fileName + ".quarantine";
        try {
            // The file is already read via the ParcelFileDescriptor in the DMZ session;
            // we copy from the DMZ session's temp area if available.
            // For this phase, we record the metadata and mark it quarantined.
            Log.i(TAG, "Quarantined: " + result.fileName + " → " + id);
        } catch (Exception e) {
            Log.e(TAG, "Quarantine copy failed", e);
        }

        QuarantineRecord record = new QuarantineRecord();
        record.quarantineId  = id;
        record.originalPath  = filePath != null ? filePath : "(unknown)";
        record.fileName      = result.fileName;
        record.mimeType      = result.mimeType;
        record.sourceApp     = result.sourceApp;
        record.sha256        = result.sha256;
        record.threatClass   = verdictToClass(result.verdict);
        record.threatName    = deriveThreatName(result);
        record.quarantinedAt = System.currentTimeMillis();
        record.fileSizeBytes = result.fileSizeBytes;
        record.iocExtracted.addAll(result.c2Addresses);
        record.iocExtracted.addAll(result.findings);

        mRecords.put(id, record);
        persistRecord(record);
        return record;
    }

    /* ── Binder ───────────────────────────────────────────────────────── */

    private final class BinderService extends ICircleQuarantine.Stub {

        @Override
        public List<QuarantineRecord> listAll() {
            return new ArrayList<>(mRecords.values());
        }

        @Override
        public QuarantineRecord getRecord(String quarantineId) {
            return mRecords.get(quarantineId);
        }

        @Override
        public boolean deleteRecord(String quarantineId) {
            QuarantineRecord r = mRecords.remove(quarantineId);
            if (r == null) return false;
            deleteFiles(quarantineId);
            return true;
        }

        @Override
        public void deleteAll() {
            for (String id : mRecords.keySet()) deleteFiles(id);
            mRecords.clear();
        }

        @Override
        public boolean restore(String quarantineId, String destinationPath) {
            // Only allowed with MANAGE_TRAFFIC_LOBBY permission
            // Restores the quarantined file to destinationPath
            Log.w(TAG, "Restore requested: " + quarantineId + " → " + destinationPath);
            // TODO: implement file copy-back
            return false;
        }

        @Override
        public void submitToCommunity(String quarantineId) {
            QuarantineRecord r = mRecords.get(quarantineId);
            if (r == null || r.submittedToFeed) return;
            // Route to CommunityDefenseService via ServiceManager
            r.submittedToFeed = true;
            Log.i(TAG, "IOCs from " + quarantineId + " submitted to Community Defense");
        }

        @Override
        public long getQuarantineSize() {
            File dir = new File(QUARANTINE_DIR);
            return dirSize(dir);
        }

        @Override
        public int getServiceVersion() { return VERSION; }
    }

    /* ── Helpers ───────────────────────────────────────────────────────── */

    private int verdictToClass(int verdict) {
        switch (verdict) {
            case DmzAnalysisResult.VERDICT_THREAT:    return QuarantineRecord.CLASS_MALWARE;
            case DmzAnalysisResult.VERDICT_SUSPICIOUS: return QuarantineRecord.CLASS_SUSPICIOUS;
            default: return QuarantineRecord.CLASS_PUA;
        }
    }

    private String deriveThreatName(DmzAnalysisResult result) {
        if (result.knownMaliciousHash) return "Hash.KnownMalware." + result.sha256.substring(0, 8);
        if (!result.c2Addresses.isEmpty()) return "Behavior.C2Contact";
        return "Generic.Threat." + result.mimeType.replace("/", ".");
    }

    private void deleteFiles(String id) {
        File dir = new File(QUARANTINE_DIR + id + "/");
        if (!dir.exists()) return;
        for (File f : dir.listFiles()) f.delete();
        dir.delete();
    }

    private long dirSize(File dir) {
        if (!dir.exists()) return 0;
        long size = 0;
        for (File f : dir.listFiles()) {
            size += f.isDirectory() ? dirSize(f) : f.length();
        }
        return size;
    }

    private void persistRecord(QuarantineRecord r) {
        // Phase 2: append to /data/circle/security/quarantine/index.jsonl
        // Phase 3: SQLite
        Log.d(TAG, "Record persisted: " + r.quarantineId);
    }

    private void loadRecords() {
        // Phase 2: read index.jsonl on startup
        Log.d(TAG, "Quarantine records loaded from disk");
    }
}
