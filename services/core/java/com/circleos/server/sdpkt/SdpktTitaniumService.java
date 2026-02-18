/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.content.Context;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.sdpkt.AnalyticsSummary;
import za.co.circleos.sdpkt.CalibrationState;
import za.co.circleos.sdpkt.DeviceLink;
import za.co.circleos.sdpkt.IShongololoWallet;
import za.co.circleos.sdpkt.LocationContext;
import za.co.circleos.sdpkt.NfcTransferRequest;
import za.co.circleos.sdpkt.ProtectionEvent;
import za.co.circleos.sdpkt.ShongololoTransaction;
import za.co.circleos.sdpkt.SyncStatus;
import za.co.circleos.sdpkt.TransactionResult;
import za.co.circleos.sdpkt.WalletBalance;
import za.co.circleos.sdpkt.WalletKey;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * SDPKT Titanium System Service.
 *
 * Hardware-grade digital cash built into Circle OS.
 * Service name: "circle.sdpkt"
 *
 * Architecture:
 *   TeeKeyManager        — ECDSA keypair in Android Keystore (StrongBox/TEE)
 *   TransactionSigner    — sign outbound, verify inbound (offline)
 *   NonceCache           — replay protection (24h nonce TTL)
 *   WalletStore          — TEE-signed balance + transaction history
 *   NfcProtocolEngine    — SDPKT NFC handshake state machine
 *   OfflineTransactionLog— persistent pending.jsonl for outbound txs (Phase 2)
 *   DoubleSpendDetector  — nonce, txId, rate-limit, blacklist checks (Phase 2)
 *   SettlementQueue      — drains pending log on network connect (Phase 2)
 *   SyncManager          — ConnectivityManager callbacks → settlement drain (Phase 2)
 *
 * NFC transport is handled by the SdpktTitanium privileged app
 * (vendor/circle/apps/SdpktTitanium) which registers a HostApduService
 * for AID F0:43:49:52:43:4C:45:53:44:50 and delegates protocol logic here
 * via this Binder.
 *
 * Phase 1: Core wallet — TEE keys, NFC P2P, sign/verify, balance management
 * Phase 2: Offline log, settlement queue, double-spend detection
 * Phase 3: Protection Engine — location rules, stress detection
 * Phase 4: Butler integration, Personality modes, lock screen quick pay
 */
public class SdpktTitaniumService extends SystemService {

    private static final String TAG          = "SdpktTitanium";
    public  static final String SERVICE_NAME = "circle.sdpkt";
    public  static final int    VERSION      = 5;

    private final BinderService  mBinderService = new BinderService();

    /* ── Phase 1 components ──────────────────────────────── */
    private TeeKeyManager        mKeyManager;
    private TransactionSigner    mSigner;
    private NonceCache           mNonceCache;
    private WalletStore          mWalletStore;
    private NfcProtocolEngine    mNfcEngine;
    private HandlerThread        mWorkerThread;
    private android.os.Handler   mWorkerHandler;

    /* ── Phase 2 components ──────────────────────────────── */
    private OfflineTransactionLog mOfflineLog;
    private DoubleSpendDetector   mDSD;
    private SettlementQueue       mSettlementQueue;
    private SyncManager           mSyncManager;

    /* ── Phase 3 components ──────────────────────────────── */
    private WalletLocationManager mLocationManager;
    private StressDetector        mStressDetector;
    private ProtectionEngine      mProtectionEngine;

    /* ── Phase 4 components ──────────────────────────────── */
    private PersonalityModeAdapter mPersonalityAdapter;

    /* ── Phase 5 components ──────────────────────────────── */
    private CalibrationManager     mCalibration;
    private ProtectionLog          mProtectionLog;
    private WearLinkManager        mWearLinkManager;
    private File                   mDataDir;

    /* ── Phase 6: multi-device pairing ───────────────────── */
    /** Map of deviceId → DeviceLink for all paired secondary devices. */
    private final java.util.concurrent.ConcurrentHashMap<String, DeviceLink>
            mLinkedDevices = new java.util.concurrent.ConcurrentHashMap<>();

    /* ── Lifecycle ────────────────────────────────────────── */

    public static class Lifecycle extends SystemService {
        private SdpktTitaniumService mService;
        public Lifecycle(Context ctx) { super(ctx); }

        @Override
        public void onStart() {
            mService = new SdpktTitaniumService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }

    public SdpktTitaniumService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mBinderService);
        Log.i(TAG, "SdpktTitaniumService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            mWorkerThread  = new HandlerThread("SdpktTitanium");
            mWorkerThread.start();
            mWorkerHandler = new android.os.Handler(mWorkerThread.getLooper());

            // Phase 1 components
            mKeyManager  = new TeeKeyManager();
            mSigner      = new TransactionSigner(mKeyManager);
            mNonceCache  = new NonceCache();
            mWalletStore = new WalletStore(mKeyManager);
            mNfcEngine   = new NfcProtocolEngine(mKeyManager, mSigner, mNonceCache);

            // Phase 2 components
            mOfflineLog      = new OfflineTransactionLog();
            mDSD             = new DoubleSpendDetector(mNonceCache, mOfflineLog, mSigner);
            mSettlementQueue = new SettlementQueue(mOfflineLog, mWalletStore, mSigner, mNonceCache);
            mSyncManager     = new SyncManager(getContext(), mSettlementQueue, mWorkerHandler);

            // Wire NfcProtocolEngine to the double-spend detector
            mNfcEngine.setDoubleSpendDetector(mDSD);

            // Restore pending transactions from disk (survived a reboot)
            mSettlementQueue.restoreFromLog();

            // Start connectivity listener
            mSyncManager.start();

            // Phase 3 — Protection Engine
            mLocationManager = new WalletLocationManager(getContext(), mWorkerHandler);
            mStressDetector  = new StressDetector(getContext());
            mProtectionEngine = new ProtectionEngine(
                    getContext(), mLocationManager, mStressDetector,
                    mWalletStore, mWorkerHandler);
            mLocationManager.start();
            mStressDetector.start(mWorkerHandler);

            // Phase 4 — Personality mode integration
            mPersonalityAdapter = new PersonalityModeAdapter();
            mPersonalityAdapter.start();
            mProtectionEngine.setPersonalityModeAdapter(mPersonalityAdapter);

            // Phase 5 — Calibration, protection log, wear link
            mDataDir        = getContext().getDir("sdpkt", Context.MODE_PRIVATE);
            mCalibration    = new CalibrationManager(mDataDir);
            mProtectionLog  = new ProtectionLog(mDataDir);
            mStressDetector.setCalibrationManager(mCalibration);
            mProtectionEngine.setPhase5Components(mProtectionLog, mCalibration);
            mWearLinkManager = new WearLinkManager(getContext(), mStressDetector);
            mWearLinkManager.start();

            // Phase 6 — load persisted linked devices
            loadLinkedDevices();

            // Auto-initialize wallet if this is a fresh device
            if (!mKeyManager.hasKey()) {
                mWorkerHandler.post(() -> {
                    WalletKey wk = mKeyManager.getOrCreateWalletKey();
                    if (wk != null) {
                        Log.i(TAG, "Wallet initialized — address: " + wk.shortAddress());
                    }
                });
            }

            Log.i(TAG, "SdpktTitaniumService boot-complete init done (v" + VERSION + ")");
        }
    }

    /* ── Binder ───────────────────────────────────────────── */

    private final class BinderService extends IShongololoWallet.Stub {

        @Override
        public boolean hasWallet() {
            return mKeyManager != null && mKeyManager.hasKey();
        }

        @Override
        public boolean initializeWallet() {
            if (mKeyManager == null) return false;
            WalletKey wk = mKeyManager.getOrCreateWalletKey();
            if (wk != null) {
                Log.i(TAG, "Wallet initialized on demand — address: " + wk.shortAddress());
            }
            return wk != null;
        }

        @Override
        public WalletKey getWalletKey() {
            if (mKeyManager == null) return null;
            return mKeyManager.getOrCreateWalletKey();
        }

        @Override
        public WalletBalance getBalance() {
            if (mWalletStore == null) return new WalletBalance();
            return mWalletStore.getBalance();
        }

        /* ── NFC session management ─────────────────── */

        @Override
        public String beginNfcSession(NfcTransferRequest request) {
            if (mNfcEngine == null) return null;
            if (request.amountCents <= 0) return null;

            // Phase 3: route through ProtectionEngine for all limit + stress checks.
            // ProtectionEngine.evaluateTransfer() also calls WalletStore.debit() on success.
            if (mProtectionEngine != null) {
                TransactionResult gate = mProtectionEngine.evaluateTransfer(
                        request.amountCents, request.lockScreenMode);
                if (!gate.success) {
                    // Return null — the calling app shows the appropriate error
                    Log.i(TAG, "Transfer gated by ProtectionEngine: " + gate.errorMessage);
                    return null;
                }
            } else {
                // Pre-Phase-3 fallback
                if (request.amountCents > mWalletStore.getBalance().availableCents) return null;
                mWalletStore.debit(request.amountCents, request.lockScreenMode);
            }

            String sessionId = mNfcEngine.beginSenderSession(request);
            Log.i(TAG, "NFC session started: " + sessionId
                    + " amount=" + request.amountCents + " cents");
            return sessionId;
        }

        @Override
        public String processNfcMessage(String sessionId, String incomingBase64) {
            if (mNfcEngine == null || sessionId == null) return null;

            NfcProtocolEngine.Session s = mNfcEngine.getSession(sessionId);
            if (s == null) {
                // Unknown session — this is the receiver: create receiver session
                String receiverSessionId = mNfcEngine.beginReceiverSession(incomingBase64);
                if (receiverSessionId == null) return null;
                return buildAdvertise(receiverSessionId);
            }

            String response = mNfcEngine.processMessage(sessionId, incomingBase64);

            // If the sender session just completed (state=DONE), enqueue for settlement
            NfcProtocolEngine.Session updated = mNfcEngine.getSession(sessionId);
            if (updated != null
                    && updated.isSender
                    && updated.state == NfcProtocolEngine.STATE_DONE
                    && updated.pendingTx != null) {
                mSettlementQueue.enqueue(updated.pendingTx);
                mNfcEngine.cancelSession(sessionId); // clean up after enqueue
            }

            return response;
        }

        private String buildAdvertise(String sessionId) {
            String pubkey = mKeyManager.getEncodedPublicKey();
            if (pubkey == null) return null;
            String deviceId;
            try {
                byte[] bytes = android.util.Base64.decode(pubkey, android.util.Base64.NO_WRAP);
                deviceId = TeeKeyManager.sha256Hex(bytes);
            } catch (Exception e) { deviceId = "unknown"; }
            String json = "{\"type\":\"advertise\",\"pubkey\":\"" + pubkey
                        + "\",\"device_id\":\"" + deviceId + "\",\"version\":2}";
            byte[] jsonBytes = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] msg = new byte[1 + jsonBytes.length];
            msg[0] = NfcProtocolEngine.MSG_ADVERTISE;
            System.arraycopy(jsonBytes, 0, msg, 1, jsonBytes.length);
            return android.util.Base64.encodeToString(msg, android.util.Base64.NO_WRAP);
        }

        @Override
        public void cancelNfcSession(String sessionId) {
            if (mNfcEngine != null) mNfcEngine.cancelSession(sessionId);
        }

        @Override
        public TransactionResult acceptIncomingTransfer(String sessionId) {
            if (mNfcEngine == null) return TransactionResult.fail(
                    TransactionResult.ERR_INTERNAL, "Service not ready");

            NfcProtocolEngine.Session s = mNfcEngine.getSession(sessionId);
            if (s == null || s.pendingTx == null) return TransactionResult.fail(
                    TransactionResult.ERR_INTERNAL, "No pending transaction");

            ShongololoTransaction tx = s.pendingTx;

            // Phase 2: double-spend check on receive
            if (mDSD != null) {
                int dsdResult = mDSD.check(tx);
                if (dsdResult != DoubleSpendDetector.OK) {
                    Log.w(TAG, "Incoming transfer rejected by DSD: "
                            + DoubleSpendDetector.describe(dsdResult));
                    mNfcEngine.cancelSession(sessionId);
                    return TransactionResult.fail(
                            TransactionResult.ERR_INVALID_SIGNATURE,
                            "Security check failed: " + DoubleSpendDetector.describe(dsdResult));
                }
                mDSD.recordAccepted(tx);
            }

            mWalletStore.credit(tx.amountCents);
            mWalletStore.addTransaction(tx);
            // Inbound transactions auto-settle immediately (funds verified via ECDSA)
            mWalletStore.settle(tx);

            WalletBalance bal = mWalletStore.getBalance();
            Log.i(TAG, "Received " + tx.amountCents + " cents from " + tx.senderDeviceId);
            return TransactionResult.ok(tx.txId, bal.availableCents, bal.dailyRemainingCents());
        }

        @Override
        public void declineIncomingTransfer(String sessionId) {
            if (mNfcEngine != null) mNfcEngine.cancelSession(sessionId);
            Log.i(TAG, "Incoming transfer declined: " + sessionId);
        }

        /* ── Transaction history ──────────────────── */

        @Override
        public List<ShongololoTransaction> getTransactions(int maxResults, long sinceEpochMs) {
            if (mWalletStore == null) return new java.util.ArrayList<>();
            return mWalletStore.getTransactions(maxResults, sinceEpochMs);
        }

        @Override
        public ShongololoTransaction getTransaction(String txId) {
            if (mWalletStore == null) return null;
            return mWalletStore.getTransaction(txId);
        }

        /* ── Limits ──────────────────────────────── */

        @Override
        public long getPerTapLimitCents() {
            return WalletStore.DEFAULT_PER_TAP_CENTS;
        }

        @Override
        public long getDailyRemainingCents() {
            if (mWalletStore == null) return 0;
            return mWalletStore.getDailyRemainingCents();
        }

        @Override
        public long getOfflineAccumulationCents() {
            if (mWalletStore == null) return 0;
            return mWalletStore.getOfflineAccumulationCents();
        }

        /* ── Phase 3: Protection Engine ──────────── */

        @Override
        public LocationContext getLocationContext() {
            if (mProtectionEngine == null) {
                return LocationContext.forType(LocationContext.TYPE_UNKNOWN, "", 0f);
            }
            return mProtectionEngine.getCurrentLocationContext();
        }

        @Override
        public boolean isProtectionActive() {
            return mProtectionEngine != null && mProtectionEngine.isProtectionActive();
        }

        @Override
        public int getStressScore() {
            return mProtectionEngine != null ? mProtectionEngine.getStressScore() : 0;
        }

        @Override
        public long getEffectivePerTapLimitCents(boolean lockScreen) {
            if (mProtectionEngine == null) {
                return lockScreen ? WalletStore.DEFAULT_LOCKSCREEN_CENTS
                                  : WalletStore.DEFAULT_PER_TAP_CENTS;
            }
            return mProtectionEngine.getEffectivePerTapCents(lockScreen);
        }

        @Override
        public long getEffectiveDailyLimitCents() {
            if (mProtectionEngine == null) return WalletStore.DEFAULT_DAILY_CENTS;
            return mProtectionEngine.getEffectiveDailyCents();
        }

        /* ── Phase 2: Settlement sync ─────────────── */

        @Override
        public List<ShongololoTransaction> getPendingTransactions() {
            if (mOfflineLog == null) return new java.util.ArrayList<>();
            return mOfflineLog.getPending();
        }

        @Override
        public SyncStatus getSyncStatus() {
            if (mSyncManager == null) {
                SyncStatus s = new SyncStatus();
                s.state = SyncStatus.STATE_OFFLINE;
                return s;
            }
            return mSyncManager.getStatus();
        }

        @Override
        public void forceSyncNow() {
            if (mSyncManager != null) mSyncManager.forceSyncNow();
        }

        @Override
        public int getPendingCount() {
            return mSettlementQueue != null ? mSettlementQueue.getPendingCount() : 0;
        }

        /* ── Phase 5: Calibration ────────────────── */

        @Override
        public CalibrationState getCalibrationState() {
            if (mProtectionEngine == null) {
                CalibrationState s = new CalibrationState();
                s.state = CalibrationState.STATE_CALIBRATED;
                return s;
            }
            return mProtectionEngine.getCalibrationState();
        }

        @Override
        public void reportFalsePositive() {
            if (mProtectionEngine != null) mProtectionEngine.reportFalsePositive();
        }

        @Override
        public void startRecalibration() {
            if (mCalibration != null) mCalibration.startRecalibration();
        }

        /* ── Phase 5: Protection log ─────────────── */

        @Override
        public List<ProtectionEvent> getProtectionEvents(int limit) {
            if (mProtectionEngine == null) return new ArrayList<>();
            return mProtectionEngine.getProtectionEvents(limit > 0 ? limit : 20);
        }

        /* ── Phase 5: Analytics ──────────────────── */

        @Override
        public AnalyticsSummary getAnalyticsSummary() {
            List<ShongololoTransaction> all = mWalletStore != null
                    ? mWalletStore.getTransactions(0, 0) : new ArrayList<>();
            int blockedCount = mProtectionLog != null
                    ? mProtectionLog.countByType(ProtectionEvent.TYPE_STRESS_BLOCK)
                        + mProtectionLog.countByType(ProtectionEvent.TYPE_LOCATION_BLOCK)
                        + mProtectionLog.countByType(ProtectionEvent.TYPE_LIMIT_BLOCK)
                    : 0;
            return WalletAnalytics.compute(all, blockedCount);
        }

        /* ── Phase 5: Export ─────────────────────── */

        @Override
        public String exportTransactions(String format) {
            if (mWalletStore == null) return null;
            List<ShongololoTransaction> all = mWalletStore.getTransactions(0, 0);
            File downloads = android.os.Environment.getExternalStoragePublicDirectory(
                    android.os.Environment.DIRECTORY_DOWNLOADS);
            File out = "json".equalsIgnoreCase(format)
                    ? ExportManager.exportJson(all, downloads)
                    : ExportManager.exportCsv(all, downloads);
            return out != null ? out.getAbsolutePath() : null;
        }

        /* ── Phase 5: Multi-device ───────────────── */

        @Override
        public List<DeviceLink> getLinkedDevices() {
            List<DeviceLink> links = new ArrayList<>();
            // Primary: this device's own wallet key
            WalletKey wk = mKeyManager != null ? mKeyManager.getOrCreateWalletKey() : null;
            if (wk != null) {
                DeviceLink primary = new DeviceLink();
                primary.deviceId         = wk.deviceId;
                primary.pubkeyHex        = wk.publicKeyHex;
                primary.label            = "This device";
                primary.role             = DeviceLink.ROLE_PRIMARY;
                primary.linkedAtMs       = 0;
                primary.lastSeenMs       = System.currentTimeMillis();
                primary.spendingLimitSats = 0; // unlimited for primary
                links.add(primary);
            }
            // Secondary: all persisted linked devices
            links.addAll(mLinkedDevices.values());
            return links;
        }

        @Override
        public boolean linkDevice(DeviceLink device) {
            if (device == null
                    || device.deviceId == null || device.deviceId.isEmpty()
                    || device.pubkeyHex == null || device.pubkeyHex.isEmpty()) {
                Log.w(TAG, "linkDevice: invalid device record");
                return false;
            }
            // Reject attempt to link primary device as secondary
            WalletKey wk = mKeyManager != null ? mKeyManager.getOrCreateWalletKey() : null;
            if (wk != null && wk.deviceId.equals(device.deviceId)) {
                Log.w(TAG, "linkDevice: cannot link primary device as secondary");
                return false;
            }
            device.role       = DeviceLink.ROLE_SECONDARY;
            device.linkedAtMs = System.currentTimeMillis();
            mLinkedDevices.put(device.deviceId, device);
            saveLinkedDevices();
            Log.i(TAG, "Linked secondary device: " + device.shortId()
                    + " label=" + device.label
                    + " spendLimit=" + device.spendingLimitSats + " sats");
            return true;
        }

        @Override
        public boolean unlinkDevice(String deviceId) {
            if (deviceId == null || deviceId.isEmpty()) return false;
            DeviceLink removed = mLinkedDevices.remove(deviceId);
            if (removed == null) {
                Log.w(TAG, "unlinkDevice: not found: " + deviceId);
                return false;
            }
            saveLinkedDevices();
            Log.i(TAG, "Unlinked device: " + removed.shortId());
            return true;
        }

        /* ── Service info ─────────────────────────── */

        @Override
        public int getServiceVersion() { return VERSION; }
    }

    // ── Phase 6: linked device persistence ───────────────────────────────────

    /**
     * Loads linked device records from linked_devices.json in the SDPKT data dir.
     * Format: JSON array of objects with fields matching DeviceLink fields.
     */
    private void loadLinkedDevices() {
        if (mDataDir == null) return;
        java.io.File file = new java.io.File(mDataDir, "linked_devices.json");
        if (!file.exists()) return;
        try {
            org.json.JSONArray arr = new org.json.JSONArray(readFileUtf8(file));
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject o = arr.getJSONObject(i);
                DeviceLink dl = new DeviceLink();
                dl.deviceId          = o.optString("deviceId");
                dl.pubkeyHex         = o.optString("pubkeyHex");
                dl.label             = o.optString("label", "Secondary device");
                dl.role              = DeviceLink.ROLE_SECONDARY;
                dl.linkedAtMs        = o.optLong("linkedAtMs", 0);
                dl.lastSeenMs        = o.optLong("lastSeenMs", 0);
                dl.spendingLimitSats = o.optLong("spendingLimitSats", 0);
                if (dl.deviceId != null && !dl.deviceId.isEmpty()) {
                    mLinkedDevices.put(dl.deviceId, dl);
                }
            }
            Log.i(TAG, "Loaded " + mLinkedDevices.size() + " linked device(s) from disk");
        } catch (Exception e) {
            Log.w(TAG, "loadLinkedDevices failed", e);
        }
    }

    /** Persists the current linked devices map to linked_devices.json. */
    private void saveLinkedDevices() {
        if (mDataDir == null) return;
        java.io.File file = new java.io.File(mDataDir, "linked_devices.json");
        try {
            org.json.JSONArray arr = new org.json.JSONArray();
            for (DeviceLink dl : mLinkedDevices.values()) {
                org.json.JSONObject o = new org.json.JSONObject();
                o.put("deviceId",          dl.deviceId);
                o.put("pubkeyHex",         dl.pubkeyHex);
                o.put("label",             dl.label != null ? dl.label : "");
                o.put("linkedAtMs",        dl.linkedAtMs);
                o.put("lastSeenMs",        dl.lastSeenMs);
                o.put("spendingLimitSats", dl.spendingLimitSats);
                arr.put(o);
            }
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file)) {
                fos.write(arr.toString().getBytes("UTF-8"));
            }
            Log.d(TAG, "Saved " + mLinkedDevices.size() + " linked device(s)");
        } catch (Exception e) {
            Log.w(TAG, "saveLinkedDevices failed", e);
        }
    }

    private static String readFileUtf8(java.io.File f) throws java.io.IOException {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[(int) f.length()];
            fis.read(buf);
            return new String(buf, "UTF-8");
        }
    }
}
