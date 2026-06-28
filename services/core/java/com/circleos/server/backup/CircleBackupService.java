/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.backup;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Binder;
import android.util.Slog;

import com.android.server.SystemService;

import za.co.circleos.backup.ICircleBackupService;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Comparator;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Circle OS encrypted local backup.
 *
 * <p>AES-256-GCM, key derived from a user-provided PIN via PBKDF2
 * (SHA-256, 100_000 iterations, 16-byte per-device salt). Backup
 * payload is the bytes of {@code /data/system_de/circle/privacy.db}
 * plus the JSON-flattened SharedPreferences files of the other Circle
 * services. App data is NOT covered -- that's Android Auto Backup's
 * lane and we leave it as-is.
 *
 * <p>Storage layout:
 * <pre>
 *   /data/circle/backup/
 *       salt                      (16 bytes, per-device, generated once)
 *       circle-backup-{ts}.cbk    (encrypted, .cbk = "circle backup")
 *       circle-backup-{ts}.cbk    (keep at most 5; FIFO prune)
 * </pre>
 *
 * <p>The cached encryption key (derived from the PIN at
 * {@link #unlockWithPin(String)}) lives in a {@code SecretKey} field
 * for the service's lifetime. We never write it to disk. Restart of
 * the service requires re-entering the PIN, by design.
 */
public final class CircleBackupService extends SystemService {

    private static final String TAG = "CircleBackup";

    public static final String SERVICE_NAME = "circle.backup";

    private static final String  BACKUP_DIR_NAME = "backup";
    private static final String  SALT_FILE_NAME  = "salt";
    private static final int     SALT_LENGTH     = 16;
    private static final int     PBKDF2_ITERS    = 100_000;
    private static final int     KEY_BITS        = 256;
    private static final int     GCM_TAG_BITS    = 128;
    private static final int     GCM_IV_LENGTH   = 12;
    private static final int     MAX_BACKUPS     = 5;
    private static final String  BACKUP_PREFIX   = "circle-backup-";
    private static final String  BACKUP_SUFFIX   = ".cbk";

    private final Context mContext;
    private final File    mBackupDir;
    private final BackupBinder mBinder = new BackupBinder();

    /** Cached AES key once the PIN has been provided. Null otherwise. */
    private volatile SecretKey mKey;

    public CircleBackupService(Context context) {
        super(context);
        mContext = context;
        final File circle = new File(context.createDeviceProtectedStorageContext().getDataDir(),
                "circle");
        mBackupDir = new File(circle, BACKUP_DIR_NAME);
        if (!mBackupDir.exists() && !mBackupDir.mkdirs()) {
            Slog.w(TAG, "Cannot create " + mBackupDir + " -- backup disabled");
        }
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_NAME);
        publishBinderService(SERVICE_NAME, mBinder);
    }

    /**
     * Internal entry point -- not on the binder -- for CircleSettings
     * to seed the encryption key. The PIN never crosses the binder
     * boundary; CircleSettings runs in the same UID as us
     * (system_server uses CircleSettings' platform-signed APK for its
     * Settings shell) so it can call this in-process.
     */
    public void unlockWithPin(String pin) {
        if (pin == null || pin.length() < 4) {
            Slog.w(TAG, "Refusing to unlock with PIN of length < 4");
            return;
        }
        try {
            mKey = deriveKey(pin);
            Slog.i(TAG, "Backup key derived; backup enabled");
        } catch (Exception e) {
            Slog.w(TAG, "Key derivation failed", e);
            mKey = null;
        }
    }

    // ------------------------------------------------------------------
    //  Binder
    // ------------------------------------------------------------------

    private final class BackupBinder extends ICircleBackupService.Stub {

        @Override
        public boolean isConfigured() {
            enforceQuery();
            return mKey != null;
        }

        @Override
        public long backupNow() {
            enforceManage();
            if (mKey == null) {
                Slog.w(TAG, "backupNow: no key -- call unlockWithPin first");
                return 0L;
            }
            try {
                final byte[] plaintext = collectBackupPayload();
                final long ts = System.currentTimeMillis();
                final File out = new File(mBackupDir, BACKUP_PREFIX + ts + BACKUP_SUFFIX);
                writeEncrypted(out, plaintext);
                pruneOld();
                Slog.i(TAG, "Backup written: " + out.getName()
                        + " (" + plaintext.length + " bytes plaintext)");
                return ts;
            } catch (Exception e) {
                Slog.w(TAG, "backupNow failed", e);
                return 0L;
            }
        }

        @Override
        public int getBackupCount() {
            enforceQuery();
            final File[] files = mBackupDir.listFiles((dir, name) ->
                    name.startsWith(BACKUP_PREFIX) && name.endsWith(BACKUP_SUFFIX));
            return files == null ? 0 : files.length;
        }

        @Override
        public boolean restore(long backupTimestamp) {
            enforceManage();
            if (mKey == null) {
                Slog.w(TAG, "restore: no key -- unlock first");
                return false;
            }
            final File in = new File(mBackupDir, BACKUP_PREFIX + backupTimestamp + BACKUP_SUFFIX);
            if (!in.exists()) {
                Slog.w(TAG, "restore: backup " + in.getName() + " not found");
                return false;
            }
            try {
                final byte[] plaintext = readEncrypted(in);
                applyBackupPayload(plaintext);
                Slog.i(TAG, "Restored backup " + in.getName());
                return true;
            } catch (Exception e) {
                Slog.w(TAG, "restore failed", e);
                return false;
            }
        }
    }

    // ------------------------------------------------------------------
    //  Crypto
    // ------------------------------------------------------------------

    private SecretKey deriveKey(String pin) throws Exception {
        final byte[] salt = ensureSalt();
        final KeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERS, KEY_BITS);
        final SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(f.generateSecret(spec).getEncoded(), "AES");
    }

    private byte[] ensureSalt() throws IOException {
        final File f = new File(mBackupDir, SALT_FILE_NAME);
        if (f.exists() && f.length() == SALT_LENGTH) {
            try (FileInputStream in = new FileInputStream(f)) {
                final byte[] b = new byte[SALT_LENGTH];
                final int n = in.read(b);
                if (n == SALT_LENGTH) return b;
            }
        }
        final byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(salt);
        }
        return salt;
    }

    private void writeEncrypted(File out, byte[] plaintext) throws Exception {
        final byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        final Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, mKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        final byte[] ciphertext = c.doFinal(plaintext);
        try (FileOutputStream fos = new FileOutputStream(out)) {
            // Header: 4 bytes magic "CBK1" + 12 bytes IV, then ciphertext.
            fos.write(new byte[]{'C','B','K','1'});
            fos.write(iv);
            fos.write(ciphertext);
        }
    }

    private byte[] readEncrypted(File in) throws Exception {
        try (FileInputStream fis = new FileInputStream(in)) {
            final byte[] header = new byte[4 + GCM_IV_LENGTH];
            int read = 0;
            while (read < header.length) {
                final int n = fis.read(header, read, header.length - read);
                if (n < 0) throw new IOException("Truncated backup header");
                read += n;
            }
            if (header[0] != 'C' || header[1] != 'B' || header[2] != 'K' || header[3] != '1') {
                throw new IOException("Bad backup magic");
            }
            final byte[] iv = Arrays.copyOfRange(header, 4, 4 + GCM_IV_LENGTH);
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final byte[] buf = new byte[8192];
            int n;
            while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
            final byte[] ciphertext = baos.toByteArray();
            final Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, mKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return c.doFinal(ciphertext);
        }
    }

    // ------------------------------------------------------------------
    //  Payload
    // ------------------------------------------------------------------

    /**
     * Collect all Circle-owned on-disk state into a single byte blob.
     * For alpha-1 this is the privacy.db file -- by far the most
     * important Circle state. SharedPreferences-backed services
     * (Update, Permission, Clipboard, Notification) regenerate
     * defaults cleanly on first run after restore, so we leave them
     * out for simplicity. Phase 2 will tar them in too.
     */
    private byte[] collectBackupPayload() throws IOException {
        final File db = new File(mContext.createDeviceProtectedStorageContext().getDataDir(),
                "circle/privacy.db");
        if (!db.exists()) {
            Slog.w(TAG, "privacy.db not present -- backup payload will be empty");
            return new byte[0];
        }
        try (FileInputStream in = new FileInputStream(db);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) baos.write(buf, 0, n);
            return baos.toByteArray();
        }
    }

    private void applyBackupPayload(byte[] plaintext) throws IOException {
        if (plaintext.length == 0) {
            Slog.i(TAG, "Empty backup payload -- nothing to restore");
            return;
        }
        final File db = new File(mContext.createDeviceProtectedStorageContext().getDataDir(),
                "circle/privacy.db");
        // SystemServer is single-threaded enough that an atomic replace is
        // overkill for alpha -- but we still write to a temp first and
        // rename, so a crash mid-write doesn't leave a torn DB.
        final File tmp = new File(db.getParentFile(), db.getName() + ".restore");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(plaintext);
        }
        if (!tmp.renameTo(db)) {
            throw new IOException("renameTo failed: " + tmp + " -> " + db);
        }
    }

    private void pruneOld() {
        final File[] files = mBackupDir.listFiles((dir, name) ->
                name.startsWith(BACKUP_PREFIX) && name.endsWith(BACKUP_SUFFIX));
        if (files == null || files.length <= MAX_BACKUPS) return;
        Arrays.sort(files, Comparator.comparingLong(File::lastModified));
        final int toDrop = files.length - MAX_BACKUPS;
        for (int i = 0; i < toDrop; i++) {
            if (files[i].delete()) {
                Slog.i(TAG, "Pruned old backup: " + files[i].getName());
            }
        }
    }

    // ------------------------------------------------------------------
    //  Permission gates
    // ------------------------------------------------------------------

    private void enforceQuery() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // Allow system + any platform-signed Circle app; otherwise require the permission.
        if (getContext().getPackageManager().checkSignatures(
                android.os.Binder.getCallingUid(), android.os.Process.SYSTEM_UID)
                        == android.content.pm.PackageManager.SIGNATURE_MATCH) return;
        getContext().enforceCallingOrSelfPermission("za.co.circleos.permission.QUERY_PRIVACY", "circle-api");
    }

    private void enforceManage() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // Allow system + any platform-signed Circle app; otherwise require the permission.
        if (getContext().getPackageManager().checkSignatures(
                android.os.Binder.getCallingUid(), android.os.Process.SYSTEM_UID)
                        == android.content.pm.PackageManager.SIGNATURE_MATCH) return;
        getContext().enforceCallingOrSelfPermission("za.co.circleos.permission.MANAGE_PRIVACY", "circle-api");
    }
}
