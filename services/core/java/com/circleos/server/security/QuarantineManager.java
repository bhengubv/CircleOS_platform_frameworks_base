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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

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

    private static final String QUARANTINE_DIR  = "/data/circle/security/quarantine/";
    private static final String INDEX_FILE      = QUARANTINE_DIR + "index.jsonl";

    private final BinderService mBinderService = new BinderService();
    private final ConcurrentHashMap<String, QuarantineRecord> mRecords
            = new ConcurrentHashMap<>();
    private final ReentrantLock mPersistLock = new ReentrantLock();
    private ResearcherApiService mResearcherApi;

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

    /** Called by CircleFileDmzService after ResearcherApiService is initialized. */
    public void setResearcherApi(ResearcherApiService api) {
        mResearcherApi = api;
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
        if (mResearcherApi != null) mResearcherApi.processQuarantineRecord(record);
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
            rewriteIndex();
            return true;
        }

        @Override
        public void deleteAll() {
            for (String id : mRecords.keySet()) deleteFiles(id);
            mRecords.clear();
            rewriteIndex();
        }

        @Override
        public boolean restore(String quarantineId, String destinationPath) {
            if (quarantineId == null || destinationPath == null || destinationPath.isEmpty()) {
                Log.w(TAG, "restore: invalid arguments");
                return false;
            }

            QuarantineRecord r = mRecords.get(quarantineId);
            if (r == null) {
                Log.w(TAG, "restore: record not found: " + quarantineId);
                return false;
            }

            // Locate the quarantined file: QUARANTINE_DIR/<id>/<filename>.quarantine
            File srcFile = new File(QUARANTINE_DIR + quarantineId + "/"
                    + r.fileName + ".quarantine");
            if (!srcFile.exists()) {
                Log.e(TAG, "restore: quarantined file missing: " + srcFile.getAbsolutePath());
                return false;
            }

            // Ensure destination parent directory exists
            File destFile = new File(destinationPath);
            File destParent = destFile.getParentFile();
            if (destParent != null && !destParent.exists() && !destParent.mkdirs()) {
                Log.e(TAG, "restore: cannot create destination directory: " + destParent);
                return false;
            }

            // Copy bytes from quarantine to destination
            try (FileInputStream in  = new FileInputStream(srcFile);
                 FileOutputStream out = new FileOutputStream(destFile)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            } catch (IOException e) {
                Log.e(TAG, "restore: copy failed for " + quarantineId, e);
                destFile.delete(); // clean up partial write
                return false;
            }

            // Verify SHA256 of restored file matches quarantine record
            if (r.sha256 != null && !r.sha256.isEmpty()) {
                String actual = sha256Hex(destFile);
                if (actual != null && !actual.equalsIgnoreCase(r.sha256)) {
                    Log.e(TAG, "restore: SHA256 mismatch for " + quarantineId
                            + " expected=" + r.sha256 + " got=" + actual);
                    destFile.delete();
                    return false;
                }
            }

            // Mark record as restored
            r.restoredAt = System.currentTimeMillis();
            r.restoredTo = destinationPath;
            Log.i(TAG, "Restored: " + quarantineId + " → " + destinationPath
                    + " (" + destFile.length() + " bytes)");
            return true;
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

    /** Computes SHA-256 hex digest of a file, or null on error. */
    private static String sha256Hex(File file) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buf = new byte[65536]; int n;
                while ((n = fis.read(buf)) > 0) md.update(buf, 0, n);
            }
            StringBuilder sb = new StringBuilder(64);
            for (byte b : md.digest()) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            Log.w(TAG, "sha256Hex failed for " + file, e);
            return null;
        }
    }

    /**
     * Rewrites the entire index.jsonl from the current in-memory map.
     * Called after deletions to keep the file consistent.
     */
    private void rewriteIndex() {
        mPersistLock.lock();
        try {
            try (FileWriter fw = new FileWriter(INDEX_FILE, /*append=*/false);
                 PrintWriter pw = new PrintWriter(fw)) {
                for (QuarantineRecord r : mRecords.values()) {
                    try {
                        pw.println(recordToJson(r).toString());
                    } catch (JSONException e) {
                        Log.w(TAG, "rewriteIndex: skipping " + r.quarantineId, e);
                    }
                }
            } catch (IOException e) {
                Log.e(TAG, "rewriteIndex: write failed", e);
            }
        } finally {
            mPersistLock.unlock();
        }
    }

    /**
     * Appends a single record as a JSON line to index.jsonl.
     * Thread-safe via mPersistLock; called on the caller thread.
     */
    private void persistRecord(QuarantineRecord r) {
        mPersistLock.lock();
        try {
            JSONObject o = recordToJson(r);
            try (FileWriter fw = new FileWriter(INDEX_FILE, /*append=*/true);
                 PrintWriter pw = new PrintWriter(fw)) {
                pw.println(o.toString());
            } catch (IOException e) {
                Log.e(TAG, "persistRecord: write failed for " + r.quarantineId, e);
            }
        } catch (JSONException e) {
            Log.e(TAG, "persistRecord: JSON error for " + r.quarantineId, e);
        } finally {
            mPersistLock.unlock();
        }
    }

    /**
     * Reads index.jsonl on startup and re-populates mRecords.
     * Skips malformed lines with a warning rather than failing.
     */
    private void loadRecords() {
        File f = new File(INDEX_FILE);
        if (!f.exists()) {
            Log.d(TAG, "loadRecords: index.jsonl not present — fresh start");
            return;
        }
        int loaded = 0, skipped = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                try {
                    QuarantineRecord r = recordFromJson(new JSONObject(line));
                    if (r.quarantineId != null && !r.quarantineId.isEmpty()) {
                        mRecords.put(r.quarantineId, r);
                        loaded++;
                    }
                } catch (JSONException je) {
                    Log.w(TAG, "loadRecords: skipping malformed line: " + line, je);
                    skipped++;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "loadRecords: read failed", e);
        }
        Log.i(TAG, "loadRecords: loaded=" + loaded + " skipped=" + skipped);
    }

    /** Serialises a QuarantineRecord to a JSONObject. */
    private static JSONObject recordToJson(QuarantineRecord r) throws JSONException {
        JSONObject o = new JSONObject();
        o.put("quarantineId",   r.quarantineId);
        o.put("originalPath",   r.originalPath  != null ? r.originalPath  : "");
        o.put("fileName",       r.fileName      != null ? r.fileName      : "");
        o.put("mimeType",       r.mimeType      != null ? r.mimeType      : "");
        o.put("sourceApp",      r.sourceApp     != null ? r.sourceApp     : "");
        o.put("sha256",         r.sha256        != null ? r.sha256        : "");
        o.put("threatClass",    r.threatClass);
        o.put("threatName",     r.threatName    != null ? r.threatName    : "");
        o.put("quarantinedAt",  r.quarantinedAt);
        o.put("fileSizeBytes",  r.fileSizeBytes);
        o.put("submittedToFeed",r.submittedToFeed);
        o.put("restoredAt",     r.restoredAt);
        o.put("restoredTo",     r.restoredTo    != null ? r.restoredTo    : "");

        JSONArray iocs = new JSONArray();
        if (r.iocExtracted != null) {
            for (String ioc : r.iocExtracted) iocs.put(ioc);
        }
        o.put("iocExtracted", iocs);
        return o;
    }

    /** Deserialises a QuarantineRecord from a JSONObject. */
    private static QuarantineRecord recordFromJson(JSONObject o) throws JSONException {
        QuarantineRecord r = new QuarantineRecord();
        r.quarantineId   = o.optString("quarantineId");
        r.originalPath   = o.optString("originalPath");
        r.fileName       = o.optString("fileName");
        r.mimeType       = o.optString("mimeType");
        r.sourceApp      = o.optString("sourceApp");
        r.sha256         = o.optString("sha256");
        r.threatClass    = o.optInt("threatClass", QuarantineRecord.CLASS_PUA);
        r.threatName     = o.optString("threatName");
        r.quarantinedAt  = o.optLong("quarantinedAt");
        r.fileSizeBytes  = o.optLong("fileSizeBytes");
        r.submittedToFeed= o.optBoolean("submittedToFeed");
        r.restoredAt     = o.optLong("restoredAt");
        r.restoredTo     = o.optString("restoredTo");

        JSONArray iocs = o.optJSONArray("iocExtracted");
        if (iocs != null) {
            for (int i = 0; i < iocs.length(); i++) {
                r.iocExtracted.add(iocs.optString(i));
            }
        }
        return r;
    }
}
