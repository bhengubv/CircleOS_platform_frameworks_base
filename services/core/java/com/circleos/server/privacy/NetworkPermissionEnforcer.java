/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.privacy;

import android.circleos.AppPrivacyPolicy;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.ServiceManager;
import android.text.TextUtils;
import android.util.Slog;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

/**
 * Circle OS network deny-by-default enforcer.
 *
 * <p>Two enforcement layers:
 *
 * <ol>
 *   <li><b>NetworkPolicyManager</b> ({@code setUidPolicy} with
 *       {@code POLICY_REJECT_METERED_BACKGROUND}) -- public, stable
 *       across AOSP versions, blocks background data on metered links.
 *       Caught by any well-behaved foreground/background-aware app.
 *   <li><b>netd firewall chain</b> ({@code INetd.firewallSetUidRule}
 *       on {@code FIREWALL_CHAIN_STANDBY}, {@code FIREWALL_RULE_DENY})
 *       -- via reflection because {@code android.net.INetd} isn't on
 *       services.core's compile classpath. Unconditional deny across
 *       both foreground and background; the chain is what AOSP itself
 *       uses for "force standby" enforcement.
 * </ol>
 *
 * <p>Both layers are applied for any package whose
 * {@link AppPrivacyPolicy#networkAllowed} is false. If either layer
 * fails (e.g. netd binder unreachable in early boot), the other still
 * carries the policy; degraded enforcement is logged but not crashing.
 *
 * <p>State is persisted to SharedPreferences so a system_server restart
 * re-establishes enforcement -- which AOSP's NetworkPolicyManager and
 * netd do not do for us; their state isn't persistent across
 * system_server respawn.
 *
 * <p>For the full "VPN-based capture of all egress" architecture
 * documented in chapter 19 of the master plan, see the Phase 4
 * {@code CircleFirewallService} -- that lands when the VPN service
 * shell is ready. This enforcer is the Phase 2 baseline.
 */
final class NetworkPermissionEnforcer {

    private static final String TAG = "CircleNetEnforce";

    private static final String PREFS_FILE       = "circle_net_enforcer";
    private static final String KEY_ENFORCED_UID = "enforced_uids";

    // NetworkPolicyManager constants reflected through to avoid a
    // hard dependency on the hidden API surface.
    private static final int POLICY_REJECT_METERED_BACKGROUND = 1;
    private static final int POLICY_NONE                      = 0;

    // netd firewall constants. Values fixed in AOSP's
    // system/netd/include/Fwmark.h and stable across r15..r20.
    private static final int FIREWALL_CHAIN_STANDBY = 3;
    private static final int FIREWALL_RULE_DENY     = 2;
    private static final int FIREWALL_RULE_ALLOW    = 1;

    private final Context              mContext;
    private final SharedPreferences    mPrefs;
    private final PackageManager       mPm;

    /** Cached INetd binder; null when unreachable. */
    private volatile Object mNetdProxy;
    private volatile Method mFirewallSetUidRule;

    NetworkPermissionEnforcer(Context context) {
        mContext = context;
        mPm      = context.getPackageManager();
        final Context dp = context.createDeviceProtectedStorageContext();
        mPrefs   = dp.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE);
        // Replay every previously-enforced uid on startup so a system_server
        // restart doesn't silently drop active denies.
        replayPersistedState();
    }

    // ------------------------------------------------------------------
    //  Public entry points (called from CirclePrivacyManagerService)
    // ------------------------------------------------------------------

    /**
     * Apply or revoke enforcement for {@code packageName} according to
     * {@code policy}. Idempotent. Logs at INFO on every state change so
     * the audit-log story is honest from day one.
     */
    void enforce(String packageName, AppPrivacyPolicy policy) {
        if (TextUtils.isEmpty(packageName) || policy == null) return;
        final int uid = uidFor(packageName);
        if (uid < 0) {
            Slog.w(TAG, "enforce: unknown package " + packageName);
            return;
        }
        if (policy.networkAllowed) {
            applyAllow(packageName, uid);
        } else {
            applyDeny(packageName, uid);
        }
    }

    /**
     * Bulk replay of every persisted enforced-uid back into the kernel
     * after a system_server respawn. system_server's own state is
     * volatile; netd's chain rules survive, but if the chain itself was
     * reset (e.g. NetworkManagementService restart) we re-establish.
     */
    private void replayPersistedState() {
        final Set<String> persisted = mPrefs.getStringSet(KEY_ENFORCED_UID, null);
        if (persisted == null || persisted.isEmpty()) return;
        for (String uidStr : persisted) {
            try {
                final int uid = Integer.parseInt(uidStr);
                applyKernelDeny(uid);
            } catch (NumberFormatException ignored) {}
        }
        Slog.i(TAG, "Replayed " + persisted.size() + " persisted enforcements");
    }

    int getEnforcedCount() {
        final Set<String> s = mPrefs.getStringSet(KEY_ENFORCED_UID, null);
        return s == null ? 0 : s.size();
    }

    // ------------------------------------------------------------------
    //  Internal -- apply / revoke
    // ------------------------------------------------------------------

    private void applyDeny(String packageName, int uid) {
        try {
            applyNetworkPolicy(uid, POLICY_REJECT_METERED_BACKGROUND);
            applyKernelDeny(uid);
            recordState(uid, true);
            Slog.i(TAG, "DENY  " + packageName + " uid=" + uid);
        } catch (Throwable t) {
            Slog.w(TAG, "applyDeny failed for " + packageName + " uid=" + uid, t);
        }
    }

    private void applyAllow(String packageName, int uid) {
        try {
            applyNetworkPolicy(uid, POLICY_NONE);
            applyKernelAllow(uid);
            recordState(uid, false);
            Slog.i(TAG, "ALLOW " + packageName + " uid=" + uid);
        } catch (Throwable t) {
            Slog.w(TAG, "applyAllow failed for " + packageName + " uid=" + uid, t);
        }
    }

    /**
     * Layer 1: NetworkPolicyManager via reflection. The public surface
     * for {@code setUidPolicy} is hidden on Android 15 -- we call into
     * the system service binder directly.
     */
    private void applyNetworkPolicy(int uid, int policy) {
        try {
            final IBinder b = ServiceManager.getService("netpolicy");
            if (b == null) {
                Slog.i(TAG, "netpolicy binder unavailable");
                return;
            }
            final Class<?> stub = Class.forName("android.net.INetworkPolicyManager$Stub");
            final Object svc = stub.getMethod("asInterface", IBinder.class).invoke(null, b);
            svc.getClass()
                    .getMethod("setUidPolicy", int.class, int.class)
                    .invoke(svc, uid, policy);
        } catch (Throwable t) {
            // NetworkPolicyManager is best-effort -- the netd layer below
            // is the authoritative enforcement. Log and continue.
            Slog.i(TAG, "NetworkPolicyManager.setUidPolicy(" + uid + ", "
                    + policy + ") failed: " + t.getMessage());
        }
    }

    /**
     * Layer 2: netd firewall chain. The authoritative kernel-level
     * block. Uses {@code FIREWALL_CHAIN_STANDBY} with rule DENY -- the
     * same mechanism AOSP itself uses to enforce App Standby.
     */
    private void applyKernelDeny(int uid) {
        invokeFirewallSetUidRule(FIREWALL_CHAIN_STANDBY, uid, FIREWALL_RULE_DENY);
    }

    private void applyKernelAllow(int uid) {
        invokeFirewallSetUidRule(FIREWALL_CHAIN_STANDBY, uid, FIREWALL_RULE_ALLOW);
    }

    private void invokeFirewallSetUidRule(int chain, int uid, int rule) {
        try {
            final Method m = ensureFirewallMethod();
            final Object proxy = ensureNetdProxy();
            if (m == null || proxy == null) return;
            m.invoke(proxy, chain, uid, rule);
        } catch (Throwable t) {
            Slog.w(TAG, "INetd.firewallSetUidRule(chain=" + chain
                    + " uid=" + uid + " rule=" + rule + ") failed", t);
        }
    }

    private Object ensureNetdProxy() throws Exception {
        if (mNetdProxy != null) return mNetdProxy;
        final IBinder b = ServiceManager.getService("netd");
        if (b == null) return null;
        final Class<?> stub = Class.forName("android.net.INetd$Stub");
        mNetdProxy = stub.getMethod("asInterface", IBinder.class).invoke(null, b);
        return mNetdProxy;
    }

    private Method ensureFirewallMethod() throws Exception {
        if (mFirewallSetUidRule != null) return mFirewallSetUidRule;
        if (mNetdProxy == null) ensureNetdProxy();
        if (mNetdProxy == null) return null;
        mFirewallSetUidRule = mNetdProxy.getClass()
                .getMethod("firewallSetUidRule", int.class, int.class, int.class);
        return mFirewallSetUidRule;
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private int uidFor(String packageName) {
        try {
            final ApplicationInfo ai = mPm.getApplicationInfo(packageName, 0);
            return ai.uid;
        } catch (PackageManager.NameNotFoundException nf) {
            return -1;
        }
    }

    private void recordState(int uid, boolean enforced) {
        synchronized (mPrefs) {
            final Set<String> current = new HashSet<>(
                    mPrefs.getStringSet(KEY_ENFORCED_UID, new HashSet<>()));
            final String key = Integer.toString(uid);
            final boolean changed = enforced ? current.add(key) : current.remove(key);
            if (changed) {
                mPrefs.edit().putStringSet(KEY_ENFORCED_UID, current).apply();
            }
        }
    }
}
