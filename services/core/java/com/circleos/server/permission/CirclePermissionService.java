/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.permission;

import android.app.AppOpsManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Binder;
import android.text.TextUtils;
import android.util.Slog;

import com.android.server.SystemService;

import za.co.circleos.permission.ICirclePermissionService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Circle OS Permission Service.
 *
 * <p>Extends the AOSP runtime permission model with a "fake response"
 * pattern for stable identifiers. When {@code setIdentifierMode(pkg,
 * "advertising_id", "fake")} is set, every call to read the advertising
 * ID (made by that package, going through AOSP's identifier provider)
 * returns a deterministic synthetic value derived from a device-wide
 * secret salt + the package name. The app sees a stable string that
 * looks real; the actual device identifier never leaves the system.
 *
 * <p>Counters: tracks total denied-permission events (forwarded from
 * AppOpsManager's onOpChanged callbacks) and total faked-identifier
 * reads (incremented every time {@link #getFakedIdentifier} returns
 * non-empty). Both surfaced by {@link ICirclePermissionService} so
 * {@link com.circleos.server.privacy.CirclePrivacyManagerService} can
 * forward them to its system-wide counter binder.
 *
 * <p>The device salt is generated lazily on first faked-id read and
 * persisted to SharedPreferences. Rotating it rotates every per-package
 * faked identifier in lockstep -- useful when a user resets their
 * privacy posture.
 */
public final class CirclePermissionService extends SystemService {

    private static final String TAG = "CirclePermission";

    /** Service name -- matches vendor/circle/sepolicy/service_contexts. */
    public static final String SERVICE_NAME = "circle.permission";

    // ---- ID type canonical names ----
    public static final String ID_ADVERTISING = "advertising_id";
    public static final String ID_SSAID       = "ssaid";
    public static final String ID_IMEI        = "imei";
    public static final String ID_MAC_WIFI    = "mac_wifi";
    public static final String ID_MAC_BT      = "mac_bluetooth";

    // ---- Identifier modes ----
    public static final String MODE_REAL = "real";
    public static final String MODE_FAKE = "fake";
    public static final String MODE_DENY = "deny";

    private static final String PREFS_FILE = "circle_permission";
    private static final String KEY_SALT   = "device_salt";
    private static final String KEY_FAKED_COUNT  = "faked_count";
    private static final String KEY_DENIED_COUNT = "denied_count";

    private final SharedPreferences mPrefs;
    private final PermissionBinder  mBinder = new PermissionBinder();
    private final OpListener        mOpListener;

    /** Cached device salt. Lazily generated on first fake-id read. */
    private volatile byte[] mDeviceSalt;

    public CirclePermissionService(Context context) {
        super(context);
        final Context dp = context.createDeviceProtectedStorageContext();
        mPrefs = dp.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE);
        mOpListener = new OpListener(context);
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_NAME);
        publishBinderService(SERVICE_NAME, mBinder);
        // Hook AppOpsManager so any denied runtime permission bumps the
        // system-wide counter -- the dashboard reads this through
        // ICirclePrivacyManagerService.getDeniedPermissionCount().
        mOpListener.attach();
    }

    // ------------------------------------------------------------------
    //  Binder
    // ------------------------------------------------------------------

    private final class PermissionBinder extends ICirclePermissionService.Stub {

        @Override
        public String getFakedIdentifier(String packageName, String idType) {
            enforceQueryPrivacy();
            if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(idType)) return "";
            // Honour per-package mode -- "real" means callers should use the
            // genuine identifier (we return empty so they fall through),
            // "deny" means we return empty too and the framework caller
            // should map that to null/empty up the chain, "fake" returns
            // the synthetic value.
            final String mode = mPrefs.getString(modeKey(packageName, idType), MODE_FAKE);
            if (!MODE_FAKE.equals(mode)) return "";

            final String value = synthesise(packageName, idType);
            incrementCounter(KEY_FAKED_COUNT);
            return value;
        }

        @Override
        public void setIdentifierMode(String packageName, String idType, String mode) {
            enforceManagePrivacy();
            if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(idType)) return;
            if (!MODE_REAL.equals(mode) && !MODE_FAKE.equals(mode) && !MODE_DENY.equals(mode)) {
                Slog.w(TAG, "Rejecting unknown mode=" + mode);
                return;
            }
            mPrefs.edit().putString(modeKey(packageName, idType), mode).apply();
            Slog.i(TAG, "setIdentifierMode(" + packageName + ", " + idType + ") = " + mode);
        }

        @Override
        public int getFakedIdentifierCount() {
            enforceQueryPrivacy();
            return mPrefs.getInt(KEY_FAKED_COUNT, 0);
        }

        @Override
        public int getDeniedPermissionCount() {
            enforceQueryPrivacy();
            return mPrefs.getInt(KEY_DENIED_COUNT, 0);
        }
    }

    // ------------------------------------------------------------------
    //  Synthetic identifier generation
    // ------------------------------------------------------------------

    /**
     * Synthesise a stable per-(package, idType) identifier shaped to
     * pass the format check most callers do. We hash the device salt +
     * package name + idType with SHA-256 and slice/format the digest
     * to match each type's canonical shape:
     *
     * <ul>
     *   <li>advertising_id -> UUID v4 form (8-4-4-4-12 hex)
     *   <li>ssaid          -> 16 hex chars
     *   <li>imei           -> 15 decimal digits with valid Luhn checksum
     *   <li>mac_wifi/bt    -> 6 hex bytes separated by colons
     * </ul>
     */
    private String synthesise(String packageName, String idType) {
        final byte[] salt = ensureSalt();
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            md.update(packageName.getBytes(StandardCharsets.UTF_8));
            md.update((byte) 0);
            md.update(idType.getBytes(StandardCharsets.UTF_8));
            final byte[] digest = md.digest();

            switch (idType) {
                case ID_ADVERTISING:
                    return formatUuid(digest);
                case ID_SSAID:
                    return hex(digest, 8); // 16 chars
                case ID_IMEI:
                    return formatImei(digest);
                case ID_MAC_WIFI:
                case ID_MAC_BT:
                    return formatMac(digest);
                default:
                    // Unknown idType -- return a 32-char hex blob so callers
                    // that compare exact-length get something predictable.
                    return hex(digest, 16);
            }
        } catch (NoSuchAlgorithmException e) {
            Slog.e(TAG, "SHA-256 unavailable -- platform broken", e);
            return "";
        }
    }

    private static String formatUuid(byte[] d) {
        final String h = hex(d, 16);
        return h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16)
                + "-" + h.substring(16, 20) + "-" + h.substring(20, 32);
    }

    /** 15-digit IMEI with valid Luhn check digit. */
    private static String formatImei(byte[] d) {
        // Use first 7 bytes -> 14 decimal digits, then append Luhn.
        final StringBuilder sb = new StringBuilder(15);
        for (int i = 0; i < 7; i++) {
            int b = d[i] & 0xff;
            sb.append((char) ('0' + (b / 10) % 10));
            sb.append((char) ('0' + b % 10));
        }
        // 14 digits so far -> compute Luhn for 15th
        int sum = 0;
        for (int i = 0; i < 14; i++) {
            int v = sb.charAt(13 - i) - '0';
            if (i % 2 == 0) {
                v *= 2;
                if (v > 9) v -= 9;
            }
            sum += v;
        }
        sb.append((char) ('0' + ((10 - (sum % 10)) % 10)));
        return sb.toString();
    }

    private static String formatMac(byte[] d) {
        final StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            int b = d[i] & 0xff;
            // Set "locally administered" bit in the first byte so the
            // synthetic MAC doesn't collide with real vendor OUIs.
            if (i == 0) b = (b & 0xfc) | 0x02;
            sb.append(hexChar(b >> 4));
            sb.append(hexChar(b & 0xf));
        }
        return sb.toString();
    }

    private static String hex(byte[] d, int bytes) {
        final StringBuilder sb = new StringBuilder(bytes * 2);
        for (int i = 0; i < bytes; i++) {
            sb.append(hexChar((d[i] >> 4) & 0xf));
            sb.append(hexChar(d[i] & 0xf));
        }
        return sb.toString();
    }

    private static char hexChar(int v) {
        return (char) (v < 10 ? '0' + v : 'a' + v - 10);
    }

    /** Lazily create & persist a 32-byte device salt. */
    private byte[] ensureSalt() {
        byte[] cached = mDeviceSalt;
        if (cached != null) return cached;
        synchronized (this) {
            cached = mDeviceSalt;
            if (cached != null) return cached;
            final String stored = mPrefs.getString(KEY_SALT, null);
            if (stored != null) {
                cached = hexDecode(stored);
            } else {
                cached = new byte[32];
                new SecureRandom().nextBytes(cached);
                mPrefs.edit().putString(KEY_SALT, hex(cached, 32)).apply();
            }
            mDeviceSalt = cached;
            return cached;
        }
    }

    private static byte[] hexDecode(String s) {
        final byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String modeKey(String pkg, String idType) {
        return "mode_" + pkg + "_" + idType;
    }

    private void incrementCounter(String key) {
        // SharedPreferences isn't atomic; for the counter use cases we have
        // (single-system-server caller, monotonic-only, displayed to humans)
        // a small race is acceptable. If contention becomes an issue we'll
        // move counters into a SQLite table with UPSERT.
        synchronized (mPrefs) {
            mPrefs.edit().putInt(key, mPrefs.getInt(key, 0) + 1).apply();
        }
    }

    // ------------------------------------------------------------------
    //  AppOpsManager bridge
    // ------------------------------------------------------------------

    private final class OpListener {
        private final AppOpsManager mOps;

        OpListener(Context ctx) {
            mOps = ctx.getSystemService(AppOpsManager.class);
        }

        void attach() {
            if (mOps == null) {
                Slog.w(TAG, "AppOpsManager unavailable -- denied-perm counter will not track");
                return;
            }
            // AppOpsManager doesn't have a global "op denied anywhere"
            // callback. We listen for changes on the ops corresponding to
            // the sensitive runtime permissions; any per-package transition
            // to MODE_IGNORED/MODE_ERRORED bumps the denied counter.
            //
            // For alpha-1 we cover the most-asked-for set; expanding to
            // the full op list is a 1-line change once telemetry shows
            // which others are worth tracking.
            final String[] ops = {
                    AppOpsManager.OPSTR_FINE_LOCATION,
                    AppOpsManager.OPSTR_COARSE_LOCATION,
                    AppOpsManager.OPSTR_CAMERA,
                    AppOpsManager.OPSTR_RECORD_AUDIO,
                    AppOpsManager.OPSTR_READ_CONTACTS,
                    AppOpsManager.OPSTR_READ_SMS,
                    AppOpsManager.OPSTR_READ_CALENDAR,
            };
            for (String op : ops) {
                try {
                    mOps.startWatchingMode(op, null,
                            (changedOp, changedPkg) -> handleOpChange(changedOp, changedPkg));
                } catch (Throwable t) {
                    Slog.w(TAG, "startWatchingMode(" + op + ") failed", t);
                }
            }
        }

        private void handleOpChange(String op, String pkg) {
            if (mOps == null || pkg == null) return;
            try {
                final int mode = mOps.unsafeCheckOpNoThrow(op,
                        android.os.Process.myUid(), pkg);
                if (mode == AppOpsManager.MODE_IGNORED
                        || mode == AppOpsManager.MODE_ERRORED) {
                    incrementCounter(KEY_DENIED_COUNT);
                }
            } catch (Throwable t) {
                // Don't let a counter bump propagate up to the AppOps thread.
                Slog.w(TAG, "handleOpChange(" + op + "," + pkg + ") failed", t);
            }
        }
    }

    // ------------------------------------------------------------------
    //  Permission gates
    // ------------------------------------------------------------------

    private void enforceQueryPrivacy() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // Allow system + any platform-signed Circle app; otherwise require the permission.
        if (getContext().getPackageManager().checkSignatures(
                android.os.Binder.getCallingUid(), android.os.Process.SYSTEM_UID)
                        == android.content.pm.PackageManager.SIGNATURE_MATCH) return;
        getContext().enforceCallingOrSelfPermission("za.co.circleos.permission.QUERY_PRIVACY", "circle-api");
    }

    private void enforceManagePrivacy() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // Allow system + any platform-signed Circle app; otherwise require the permission.
        if (getContext().getPackageManager().checkSignatures(
                android.os.Binder.getCallingUid(), android.os.Process.SYSTEM_UID)
                        == android.content.pm.PackageManager.SIGNATURE_MATCH) return;
        getContext().enforceCallingOrSelfPermission("za.co.circleos.permission.MANAGE_PRIVACY", "circle-api");
    }
}
