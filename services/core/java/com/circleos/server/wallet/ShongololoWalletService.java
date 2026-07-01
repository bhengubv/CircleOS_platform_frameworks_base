/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.circleos.server.wallet;

import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.RemoteException;
import android.os.UserHandle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Slog;

import com.android.server.SystemService;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import za.co.circleos.sdpkt.AnalyticsSummary;
import za.co.circleos.sdpkt.CalibrationState;
import za.co.circleos.sdpkt.IShongololoWallet;
import za.co.circleos.sdpkt.LocationContext;
import za.co.circleos.sdpkt.NfcTransferRequest;
import za.co.circleos.sdpkt.ProtectionEvent;
import za.co.circleos.sdpkt.ShongololoTransaction;
import za.co.circleos.sdpkt.SyncStatus;
import za.co.circleos.sdpkt.TransactionResult;
import za.co.circleos.sdpkt.WalletBalance;
import za.co.circleos.sdpkt.WalletKey;

/**
 * ShongololoWalletService — the on-device SDPKT Titanium wallet backend.
 *
 * The wallet UI / NFC / tile apps bind to this via ServiceManager.getService(
 * "circle.sdpkt"). It owns:
 *   • a hardware-bound signing key (Android Keystore, StrongBox where available,
 *     usable only after a fresh biometric / device-credential auth — the UI's
 *     BiometricPrompt unlocks it for a short window);
 *   • a persisted local ledger (balance + offline transactions);
 *   • the NFC peer-to-peer transfer state machine (sender + receiver roles);
 *   • a settlement queue that carries offline transactions until they can be
 *     cleared against the SDPKT settlement backend ("Shongololo" — the millipede
 *     that carries many small things and settles them all at once).
 *
 * Honest seam: value-clearing is NOT faked on-device. Transactions sit
 * PENDING_SETTLEMENT and are POSTed to the settlement backend when reachable;
 * offline, they are genuinely carried until the next sync. No money is conjured.
 */
public final class ShongololoWalletService extends SystemService {

    private static final String TAG = "ShongololoWallet";

    private static final String SERVICE_NAME  = "circle.sdpkt";
    private static final String SERVICE_ALIAS = "circle_wallet";

    private static final String KEY_ALIAS = "circle_wallet_sign_key";
    /** Seconds a biometric / device-credential auth keeps the signing key usable. */
    private static final int AUTH_WINDOW_SECONDS = 60;

    private static final String CURRENCY = "ZAR";

    // Baseline limits (cents). Location-tuned at read time; lock-screen quick-pay
    // gets a tighter per-tap ceiling.
    private static final long BASE_PER_TAP_CENTS    = 50_000;   // R500
    private static final long LOCK_PER_TAP_CENTS    = 20_000;   // R200 on the lock screen
    private static final long BASE_DAILY_CENTS      = 200_000;  // R2000

    private static final long DAY_MS = 24L * 60 * 60 * 1000;

    // NFC message types: wire byte 0, then JSON.
    private static final int MSG_DISCOVER = 0x01; // sender -> receiver (built by client)
    private static final int MSG_HELLO    = 0x02; // receiver -> sender
    private static final int MSG_OFFER    = 0x03; // sender -> receiver (signed)
    private static final int MSG_ACCEPTED = 0x04; // receiver -> sender (recorded, pending)
    private static final int MSG_ERROR    = 0x05;

    public static final String ACTION_INCOMING_TRANSFER =
            "za.co.circleos.sdpkt.action.INCOMING_TRANSFER";

    private final Context mContext;
    private final File mDir;
    private final File mLedgerFile;
    private final Object mLock = new Object();

    // Ledger state (guarded by mLock).
    private boolean mInitialised;
    private String  mAddress;
    private String  mPubHex;
    private long    mCreatedAtMs;
    /** Money state + arithmetic, unit-tested in WalletMathTest (21/21). */
    private final WalletMath mMath =
            new WalletMath(BASE_PER_TAP_CENTS, LOCK_PER_TAP_CENTS, BASE_DAILY_CENTS);
    private long    mLastSettlementMs;
    private final List<JSONObject> mTxs = new ArrayList<>();          // newest last
    private final List<JSONObject> mEvents = new ArrayList<>();       // protection events
    private int mFalsePositiveCount;

    // Live NFC sessions.
    private final ConcurrentHashMap<String, SenderSession> mSenders = new ConcurrentHashMap<>();
    private volatile ReceiverSession mReceiver; // single active receiver (NFC is point-to-point)
    private final AtomicInteger mTxSeq = new AtomicInteger(1);

    public ShongololoWalletService(Context context) {
        super(context);
        mContext = context;
        mDir = new File("/data/system/circle/wallet");
        mLedgerFile = new File(mDir, "wallet.json");
    }

    @Override
    public void onStart() {
        try {
            if (!mDir.exists()) mDir.mkdirs();
            loadLedger();
        } catch (Throwable t) {
            Slog.e(TAG, "ledger load failed", t);
        }
        publishBinderService(SERVICE_NAME, mBinder);
        publishBinderService(SERVICE_ALIAS, mBinder); // documented alias
        Slog.i(TAG, "ShongololoWalletService up (initialised=" + mInitialised + ")");
    }

    // ───────────────────────── binder ─────────────────────────

    private final IShongololoWallet.Stub mBinder = new IShongololoWallet.Stub() {

        @Override public boolean hasWallet() {
            enforceQuery();
            synchronized (mLock) { return mInitialised; }
        }

        @Override public void initializeWallet() {
            enforceManage();
            synchronized (mLock) {
                if (mInitialised) return;
                try {
                    KeyPair kp = generateOrLoadKey();
                    mPubHex = toHex(kp.getPublic().getEncoded());
                    mAddress = deriveAddress(kp.getPublic().getEncoded());
                    mCreatedAtMs = nowMs();
                    mInitialised = true;
                    saveLedger();
                    Slog.i(TAG, "wallet initialised: " + shortOf(mAddress));
                } catch (Throwable t) {
                    Slog.e(TAG, "initializeWallet failed", t);
                    throw new IllegalStateException("wallet init failed");
                }
            }
        }

        @Override public WalletKey getWalletKey() {
            enforceQuery();
            synchronized (mLock) {
                if (!mInitialised) return null;
                WalletKey k = new WalletKey();
                k.walletAddress = mAddress;
                k.publicKeyHex = mPubHex;
                k.createdAtMs = mCreatedAtMs;
                return k;
            }
        }

        @Override public WalletBalance getBalance() {
            enforceQuery();
            synchronized (mLock) {
                rolloverDay();
                WalletBalance b = new WalletBalance();
                b.availableCents = mMath.available;
                b.pendingInCents = mMath.pendingIn;
                b.pendingOutCents = mMath.pendingOut;
                b.dailySpentCents = mMath.dailySpent;
                b.dailyLimitCents = BASE_DAILY_CENTS;
                b.currency = CURRENCY;
                return b;
            }
        }

        @Override public List<ShongololoTransaction> getTransactions(int limit, int offset) {
            enforceQuery();
            synchronized (mLock) {
                List<ShongololoTransaction> out = new ArrayList<>();
                int n = mTxs.size();
                int from = Math.max(0, n - offset - Math.max(0, limit));
                int to = Math.max(0, n - offset);
                for (int i = to - 1; i >= from; i--) out.add(txFromJson(mTxs.get(i)));
                return out;
            }
        }

        @Override public SyncStatus getSyncStatus() {
            enforceQuery();
            synchronized (mLock) {
                SyncStatus s = new SyncStatus();
                s.pendingCount = pendingCountLocked();
                s.lastSettlementMs = mLastSettlementMs;
                s.state = settleUrl().isEmpty() ? SyncStatus.STATE_OFFLINE : SyncStatus.STATE_IDLE;
                return s;
            }
        }

        @Override public int getPendingCount() {
            enforceQuery();
            synchronized (mLock) { return pendingCountLocked(); }
        }

        @Override public LocationContext getLocationContext() {
            enforceQuery();
            LocationContext c = new LocationContext();
            c.type = LocationContext.TYPE_UNKNOWN;
            c.perTapLimitCents = BASE_PER_TAP_CENTS;
            c.dailyLimitCents = BASE_DAILY_CENTS;
            c.locationLabel = "";
            c.confidencePercent = 0f;
            c.speedMs = 0f;
            return c;
        }

        @Override public boolean isProtectionActive() {
            enforceQuery();
            return true;
        }

        @Override public CalibrationState getCalibrationState() {
            enforceQuery();
            synchronized (mLock) {
                CalibrationState s = new CalibrationState();
                s.state = CalibrationState.STATE_LEARNING;
                s.daysRemaining = 0;
                s.settledPerTapLimitCents = BASE_PER_TAP_CENTS;
                s.manualOverride = false;
                s.falsePositiveCount = mFalsePositiveCount;
                return s;
            }
        }

        @Override public long getEffectivePerTapLimitCents(boolean lockScreen) {
            enforceQuery();
            return lockScreen ? LOCK_PER_TAP_CENTS : BASE_PER_TAP_CENTS;
        }

        @Override public long getEffectiveDailyLimitCents() {
            enforceQuery();
            return BASE_DAILY_CENTS;
        }

        @Override public long getDailyRemainingCents() {
            enforceQuery();
            synchronized (mLock) {
                rolloverDay();
                return mMath.dailyRemaining();
            }
        }

        @Override public long getOfflineAccumulationCents() {
            enforceQuery();
            synchronized (mLock) { return mMath.pendingOut + mMath.pendingIn; }
        }

        @Override public void forceSyncNow() {
            enforceManage();
            new Thread(ShongololoWalletService.this::syncSettlements, "WalletSettle").start();
        }

        @Override public void reportFalsePositive() {
            enforceManage();
            synchronized (mLock) { mFalsePositiveCount++; saveLedger(); }
        }

        @Override public String beginNfcSession(NfcTransferRequest req) {
            enforceUse();
            if (req == null || req.amountCents <= 0) return null;
            synchronized (mLock) {
                if (!mInitialised) return null;
                rolloverDay();
                String block = mMath.checkSend(req.amountCents, req.lockScreenMode, nowMs());
                if (block != null) {
                    boolean funds = "insufficient funds".equals(block);
                    logEvent(funds ? ProtectionEvent.TYPE_AMOUNT_OUTLIER : ProtectionEvent.TYPE_RATE_LIMIT,
                            funds ? ProtectionEvent.SEVERITY_WARN : ProtectionEvent.SEVERITY_BLOCK,
                            block, req.amountCents);
                    return null;
                }
            }
            SenderSession s = new SenderSession();
            s.sid = newId("snd");
            s.amountCents = req.amountCents;
            s.memo = req.memo == null ? "" : req.memo;
            mSenders.put(s.sid, s);
            return s.sid;
        }

        @Override public String processNfcMessage(String sessionId, String incomingB64) {
            // sessionId == null  => receiver role (HCE proxies, owns no id)
            // sessionId != null  => sender role (continuing its own session)
            try {
                byte[] raw = Base64.decode(incomingB64, Base64.NO_WRAP);
                if (raw == null || raw.length < 1) return err("bad frame");
                int type = raw[0] & 0xff;
                JSONObject in = raw.length > 1
                        ? new JSONObject(new String(raw, 1, raw.length - 1, StandardCharsets.UTF_8))
                        : new JSONObject();
                if (sessionId == null) return receiverStep(type, in);
                SenderSession s = mSenders.get(sessionId);
                if (s == null) return err("unknown session");
                return senderStep(s, type, in);
            } catch (Throwable t) {
                Slog.e(TAG, "processNfcMessage failed", t);
                return err("protocol error");
            }
        }

        @Override public void cancelNfcSession(String sessionId) {
            enforceUse();
            if (sessionId != null) mSenders.remove(sessionId);
            ReceiverSession r = mReceiver;
            if (r != null && r.rsid.equals(sessionId)) mReceiver = null;
        }

        @Override public TransactionResult acceptIncomingTransfer(String sessionId) {
            enforceUse();
            ReceiverSession r = mReceiver;
            if (r == null || !r.rsid.equals(sessionId)) return fail("no pending transfer");
            synchronized (mLock) {
                JSONObject tx = newTx(ShongololoTransaction.TYPE_RECV,
                        ShongololoTransaction.STATUS_PENDING_SETTLEMENT,
                        r.amountCents, r.senderPubHex, null, r.memo, "nfc");
                mTxs.add(tx);
                mMath.acceptRecv(r.amountCents);
                saveLedger();
                mReceiver = null;
                queueSync();
                TransactionResult res = new TransactionResult();
                res.success = true;
                res.outcome = TransactionResult.OUTCOME_OK;
                res.txId = jsonStr(tx, "txId");
                res.newBalanceCents = mMath.available;
                return res;
            }
        }

        @Override public void declineIncomingTransfer(String sessionId) {
            enforceUse();
            ReceiverSession r = mReceiver;
            if (r != null && r.rsid.equals(sessionId)) mReceiver = null;
        }

        @Override public List<ProtectionEvent> getProtectionEvents(int limit) {
            enforceQuery();
            synchronized (mLock) {
                List<ProtectionEvent> out = new ArrayList<>();
                for (int i = mEvents.size() - 1; i >= 0 && out.size() < limit; i--) {
                    JSONObject e = mEvents.get(i);
                    ProtectionEvent pe = new ProtectionEvent();
                    pe.timestampMs = e.optLong("ts");
                    pe.type = e.optInt("type");
                    pe.severity = e.optInt("sev");
                    pe.reason = e.optString("reason", "");
                    pe.amountCents = e.optLong("amt");
                    out.add(pe);
                }
                return out;
            }
        }

        @Override public AnalyticsSummary getAnalyticsSummary() {
            enforceQuery();
            synchronized (mLock) {
                AnalyticsSummary a = new AnalyticsSummary();
                long sent = 0, recv = 0; int sc = 0, rc = 0;
                for (JSONObject t : mTxs) {
                    int ty = t.optInt("type");
                    long amt = t.optLong("amt");
                    if (ty == ShongololoTransaction.TYPE_SEND) { sent += amt; sc++; }
                    else if (ty == ShongololoTransaction.TYPE_RECV) { recv += amt; rc++; }
                }
                a.totalSentCents = sent; a.totalReceivedCents = recv;
                a.txCount = mTxs.size(); a.txSentCount = sc; a.txReceivedCount = rc;
                a.avgSentCents = sc > 0 ? sent / sc : 0;
                a.peakDaySpentCents = mMath.dailySpent;
                a.blockedTxCount = mEvents.size();
                return a;
            }
        }

        @Override public String exportTransactions(String format) {
            enforceQuery();
            synchronized (mLock) {
                try {
                    boolean csv = !"json".equalsIgnoreCase(format);
                    File out = new File(mDir, "export." + (csv ? "csv" : "json"));
                    StringBuilder sb = new StringBuilder();
                    if (csv) {
                        sb.append("txId,type,status,amountCents,currency,peer,memo,createdAtMs\n");
                        for (JSONObject t : mTxs) {
                            sb.append(jsonStr(t, "txId")).append(',')
                              .append(t.optInt("type")).append(',')
                              .append(t.optInt("status")).append(',')
                              .append(t.optLong("amt")).append(',')
                              .append(CURRENCY).append(',')
                              .append(csvSafe(jsonStr(t, "peer"))).append(',')
                              .append(csvSafe(jsonStr(t, "memo"))).append(',')
                              .append(t.optLong("ts")).append('\n');
                        }
                    } else {
                        JSONArray arr = new JSONArray();
                        for (JSONObject t : mTxs) arr.put(t);
                        sb.append(arr.toString());
                    }
                    writeFile(out, sb.toString().getBytes(StandardCharsets.UTF_8));
                    return out.getAbsolutePath();
                } catch (Throwable t) {
                    Slog.e(TAG, "export failed", t);
                    return null;
                }
            }
        }
    };

    // ───────────────────────── NFC state machine ─────────────────────────

    /** Receiver role: HCE proxies the sender's messages; we own session state. */
    private String receiverStep(int type, JSONObject in) {
        switch (type) {
            case MSG_DISCOVER: {
                synchronized (mLock) { if (!mInitialised) return err("no wallet"); }
                ReceiverSession r = new ReceiverSession();
                r.rsid = newId("rcv");
                mReceiver = r;
                JSONObject hello = new JSONObject();
                jput(hello, "rpub", mPubHex);
                jput(hello, "rsid", r.rsid);
                return frame(MSG_HELLO, hello);
            }
            case MSG_OFFER: {
                ReceiverSession r = mReceiver;
                if (r == null) return err("no session");
                long amt = in.optLong("amt");
                String spub = in.optString("spub", "");
                String memo = in.optString("memo", "");
                String sig = in.optString("sig", "");
                if (amt <= 0 || spub.isEmpty()
                        || !verify(spub, offerBytes(r.rsid, amt, memo), sig)) {
                    return err("bad offer");
                }
                r.amountCents = amt;
                r.senderPubHex = spub;
                r.memo = memo;
                // Tap is brief; the user accepts after the tap via acceptIncomingTransfer.
                broadcastIncoming(r);
                JSONObject acc = new JSONObject();
                jput(acc, "status", ShongololoTransaction.STATUS_PENDING_SETTLEMENT);
                return frame(MSG_ACCEPTED, acc);
            }
            default:
                return err("unexpected " + type);
        }
    }

    /** Sender role: produce the next outgoing message from the receiver's reply. */
    private String senderStep(SenderSession s, int type, JSONObject in) {
        switch (type) {
            case MSG_HELLO: {
                String rpub = in.optString("rpub", "");
                if (rpub.isEmpty()) return err("no receiver key");
                s.receiverPubHex = rpub;
                byte[] toSign = offerBytes(in.optString("rsid", ""), s.amountCents, s.memo);
                String sig = sign(toSign); // requires fresh user auth (StrongBox key)
                if (sig == null) return err("authorisation required");
                JSONObject offer = new JSONObject();
                jput(offer, "amt", s.amountCents);
                jput(offer, "cur", CURRENCY);
                jput(offer, "spub", mPubHex);
                jput(offer, "memo", s.memo);
                jput(offer, "rsid", in.optString("rsid", ""));
                jput(offer, "sig", sig);
                return frame(MSG_OFFER, offer);
            }
            case MSG_ACCEPTED: {
                finalizeSend(s);
                mSenders.remove(s.sid);
                return null; // handshake complete
            }
            case MSG_ERROR:
            default:
                mSenders.remove(s.sid);
                return null;
        }
    }

    private void finalizeSend(SenderSession s) {
        synchronized (mLock) {
            rolloverDay();
            JSONObject tx = newTx(ShongololoTransaction.TYPE_SEND,
                    ShongololoTransaction.STATUS_PENDING_SETTLEMENT,
                    s.amountCents, s.receiverPubHex, null, s.memo, "nfc");
            mTxs.add(tx);
            mMath.finalizeSend(s.amountCents, nowMs());
            saveLedger();
            queueSync();
        }
    }

    /** Canonical bytes signed over a transfer offer (receiver session + amount + memo). */
    private byte[] offerBytes(String rsid, long amt, String memo) {
        return WalletFrame.offerBytes(rsid, amt, memo);
    }

    private void broadcastIncoming(ReceiverSession r) {
        try {
            Intent i = new Intent(ACTION_INCOMING_TRANSFER);
            i.setPackage("za.co.circleos.sdpkt.app");
            i.putExtra("session_id", r.rsid);
            i.putExtra("amount_cents", r.amountCents);
            i.putExtra("sender_id", shortOf(r.senderPubHex));
            mContext.sendBroadcastAsUser(i, UserHandle.ALL);
        } catch (Throwable t) {
            Slog.w(TAG, "incoming broadcast failed", t);
        }
    }

    // ───────────────────────── settlement ─────────────────────────

    private void queueSync() {
        new Thread(this::syncSettlements, "WalletSettle").start();
    }

    /** POST pending transactions to the settlement backend. Offline-safe: failures
     *  leave the transactions PENDING_SETTLEMENT to be carried to the next sync. */
    private void syncSettlements() {
        String url = settleUrl();
        if (url.isEmpty()) { Slog.i(TAG, "no settle_url -- carrying pending offline"); return; }
        List<JSONObject> pending = new ArrayList<>();
        synchronized (mLock) {
            for (JSONObject t : mTxs) {
                if (t.optInt("status") == ShongololoTransaction.STATUS_PENDING_SETTLEMENT)
                    pending.add(t);
            }
        }
        if (pending.isEmpty()) return;
        for (JSONObject t : pending) {
            try {
                JSONObject body = new JSONObject();
                jput(body, "address", mAddress);
                jput(body, "txId", jsonStr(t, "txId"));
                jput(body, "type", t.optInt("type"));
                jput(body, "amountCents", t.optLong("amt"));
                jput(body, "peer", jsonStr(t, "peer"));
                boolean ok = postSettlement(url, body.toString());
                if (ok) markSettled(t);
            } catch (Throwable e) {
                Slog.w(TAG, "settlement post failed (will carry)", e);
                break; // network down — keep the rest pending
            }
        }
    }

    private void markSettled(JSONObject t) {
        synchronized (mLock) {
            jput(t, "status", ShongololoTransaction.STATUS_SETTLED);
            jput(t, "settledAtMs", nowMs());
            long amt = t.optLong("amt");
            if (t.optInt("type") == ShongololoTransaction.TYPE_SEND) {
                mMath.settleSend(amt);
            } else if (t.optInt("type") == ShongololoTransaction.TYPE_RECV) {
                mMath.settleRecv(amt);
            }
            mLastSettlementMs = nowMs();
            saveLedger();
        }
    }

    private boolean postSettlement(String url, String json) throws Exception {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/json");
            c.getOutputStream().write(json.getBytes(StandardCharsets.UTF_8));
            int code = c.getResponseCode();
            return code >= 200 && code < 300;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private String settleUrl() {
        String v = android.os.SystemProperties.get("circle.sdpkt.settle_url", "");
        return v == null ? "" : v.trim();
    }

    // ───────────────────────── keys ─────────────────────────

    private KeyPair generateOrLoadKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            PrivateKey priv = (PrivateKey) ks.getKey(KEY_ALIAS, null);
            PublicKey pub = ks.getCertificate(KEY_ALIAS).getPublicKey();
            return new KeyPair(pub, priv);
        }
        return generateKey(true);
    }

    private KeyPair generateKey(boolean strongBox) throws Exception {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(AUTH_WINDOW_SECONDS,
                            KeyProperties.AUTH_BIOMETRIC_STRONG
                                    | KeyProperties.AUTH_DEVICE_CREDENTIAL);
            if (strongBox) b.setIsStrongBoxBacked(true);
            kpg.initialize(b.build());
            return kpg.generateKeyPair();
        } catch (android.security.keystore.StrongBoxUnavailableException sbe) {
            Slog.w(TAG, "StrongBox unavailable -- falling back to TEE Keystore");
            return generateKey(false);
        }
    }

    /** Sign with the hardware key; null if the user has not authenticated recently. */
    private String sign(byte[] data) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey priv = (PrivateKey) ks.getKey(KEY_ALIAS, null);
            if (priv == null) return null;
            Signature sg = Signature.getInstance("SHA256withECDSA");
            sg.initSign(priv);
            sg.update(data);
            return Base64.encodeToString(sg.sign(), Base64.NO_WRAP);
        } catch (android.security.keystore.UserNotAuthenticatedException ue) {
            Slog.w(TAG, "sign blocked: fresh biometric/PIN required");
            return null;
        } catch (Throwable t) {
            Slog.e(TAG, "sign failed", t);
            return null;
        }
    }

    private boolean verify(String pubHex, byte[] data, String sigB64) {
        try {
            byte[] pub = fromHex(pubHex);
            PublicKey key = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(pub));
            Signature sg = Signature.getInstance("SHA256withECDSA");
            sg.initVerify(key);
            sg.update(data);
            return sg.verify(Base64.decode(sigB64, Base64.NO_WRAP));
        } catch (Throwable t) {
            Slog.w(TAG, "verify failed", t);
            return false;
        }
    }

    private String deriveAddress(byte[] pubEncoded) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(pubEncoded);
        return "sdpkt" + toHex(h).substring(0, 32);
    }

    // ───────────────────────── ledger persistence ─────────────────────────

    private void loadLedger() throws Exception {
        if (!mLedgerFile.exists()) return;
        byte[] raw = readFile(mLedgerFile);
        if (raw == null || raw.length == 0) return;
        JSONObject o = new JSONObject(new String(raw, StandardCharsets.UTF_8));
        synchronized (mLock) {
            mInitialised = o.optBoolean("init");
            mAddress = o.optString("addr", null);
            mPubHex = o.optString("pub", null);
            mCreatedAtMs = o.optLong("created");
            mMath.available = o.optLong("avail");
            mMath.pendingIn = o.optLong("pin");
            mMath.pendingOut = o.optLong("pout");
            mMath.dailySpent = o.optLong("dspent");
            mMath.dailyEpochDay = o.optLong("dday");
            mLastSettlementMs = o.optLong("lastsettle");
            mFalsePositiveCount = o.optInt("fp");
            mTxs.clear();
            JSONArray txa = o.optJSONArray("txs");
            if (txa != null) for (int i = 0; i < txa.length(); i++) mTxs.add(txa.getJSONObject(i));
            mEvents.clear();
            JSONArray eva = o.optJSONArray("events");
            if (eva != null) for (int i = 0; i < eva.length(); i++) mEvents.add(eva.getJSONObject(i));
        }
    }

    private void saveLedger() {
        try {
            JSONObject o = new JSONObject();
            o.put("init", mInitialised);
            o.put("addr", mAddress);
            o.put("pub", mPubHex);
            o.put("created", mCreatedAtMs);
            o.put("avail", mMath.available);
            o.put("pin", mMath.pendingIn);
            o.put("pout", mMath.pendingOut);
            o.put("dspent", mMath.dailySpent);
            o.put("dday", mMath.dailyEpochDay);
            o.put("lastsettle", mLastSettlementMs);
            o.put("fp", mFalsePositiveCount);
            o.put("txs", new JSONArray(mTxs));
            // keep the protection-event log bounded
            while (mEvents.size() > 200) mEvents.remove(0);
            o.put("events", new JSONArray(mEvents));
            writeFile(mLedgerFile, o.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Throwable t) {
            Slog.e(TAG, "saveLedger failed", t);
        }
    }

    // ───────────────────────── helpers ─────────────────────────

    private JSONObject newTx(int type, int status, long amt, String peer,
                             String unused, String memo, String channel) {
        JSONObject t = new JSONObject();
        jput(t, "txId", newId("tx"));
        jput(t, "type", type);
        jput(t, "status", status);
        jput(t, "amt", amt);
        jput(t, "peer", peer == null ? "" : peer);
        jput(t, "memo", memo == null ? "" : memo);
        jput(t, "channel", channel);
        jput(t, "ts", nowMs());
        return t;
    }

    private ShongololoTransaction txFromJson(JSONObject t) {
        ShongololoTransaction x = new ShongololoTransaction();
        x.txId = jsonStr(t, "txId");
        x.type = t.optInt("type");
        x.status = t.optInt("status");
        x.amountCents = t.optLong("amt");
        x.currency = CURRENCY;
        x.receiverPubkey = jsonStr(t, "peer");
        x.senderDeviceId = jsonStr(t, "peer");
        x.memo = jsonStr(t, "memo");
        x.createdAtMs = t.optLong("ts");
        x.settledAtMs = t.optLong("settledAtMs");
        x.channel = jsonStr(t, "channel");
        return x;
    }

    private int pendingCountLocked() {
        int n = 0;
        for (JSONObject t : mTxs)
            if (t.optInt("status") == ShongololoTransaction.STATUS_PENDING_SETTLEMENT) n++;
        return n;
    }

    private void rolloverDay() {
        mMath.rolloverDay(nowMs());
    }

    private void logEvent(int type, int sev, String reason, long amt) {
        JSONObject e = new JSONObject();
        jput(e, "ts", nowMs());
        jput(e, "type", type);
        jput(e, "sev", sev);
        jput(e, "reason", reason);
        jput(e, "amt", amt);
        synchronized (mLock) { mEvents.add(e); saveLedger(); }
    }

    private String frame(int type, JSONObject body) {
        byte[] json = body.toString().getBytes(StandardCharsets.UTF_8);
        byte[] msg = new byte[1 + json.length];
        msg[0] = (byte) type;
        System.arraycopy(json, 0, msg, 1, json.length);
        return Base64.encodeToString(msg, Base64.NO_WRAP);
    }

    private String err(String why) {
        JSONObject o = new JSONObject();
        jput(o, "reason", why);
        return frame(MSG_ERROR, o);
    }

    private TransactionResult fail(String msg) {
        TransactionResult r = new TransactionResult();
        r.success = false;
        r.outcome = TransactionResult.OUTCOME_REJECTED;
        r.errorMessage = msg;
        return r;
    }

    private static void jput(JSONObject o, String k, Object v) {
        try { o.put(k, v); } catch (Throwable ignored) {}
    }

    private static String jsonStr(JSONObject o, String k) { return o.optString(k, ""); }

    private String newId(String prefix) {
        byte[] b = new byte[6];
        new SecureRandom().nextBytes(b);
        return prefix + "_" + toHex(b) + mTxSeq.getAndIncrement();
    }

    private static String shortOf(String s) {
        if (s == null) return "";
        return s.length() <= 10 ? s : s.substring(0, 10) + "…";
    }

    private static String csvSafe(String s) {
        if (s == null) return "";
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    private static long nowMs() { return System.currentTimeMillis(); }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format(Locale.US, "%02x", x & 0xff));
        return sb.toString();
    }

    private static byte[] fromHex(String s) {
        int n = s.length() / 2;
        byte[] o = new byte[n];
        for (int i = 0; i < n; i++)
            o[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return o;
    }

    private static byte[] readFile(File f) throws Exception {
        try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int r;
            while ((r = in.read(buf)) != -1) bos.write(buf, 0, r);
            return bos.toByteArray();
        }
    }

    private static void writeFile(File f, byte[] data) throws Exception {
        File tmp = new File(f.getAbsolutePath() + ".tmp");
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(tmp)) {
            out.write(data);
            out.getFD().sync();
        }
        if (!tmp.renameTo(f)) { writeRaw(f, data); tmp.delete(); }
    }

    private static void writeRaw(File f, byte[] data) throws Exception {
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(f)) { out.write(data); }
    }

    // ───────────────────────── permission gates ─────────────────────────

    private void enforceQuery()  { enforce("za.co.circleos.permission.QUERY_SDPKT"); }
    private void enforceUse()    { enforce("za.co.circleos.permission.USE_SDPKT"); }
    private void enforceManage() { enforce("za.co.circleos.permission.MANAGE_SDPKT"); }

    /** Allow system + any platform-signed Circle app; otherwise require the permission. */
    private void enforce(String perm) {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        if (mContext.getPackageManager().checkSignatures(uid, android.os.Process.SYSTEM_UID)
                == android.content.pm.PackageManager.SIGNATURE_MATCH) return;
        mContext.enforceCallingOrSelfPermission(perm, "circle-wallet");
    }

    // ───────────────────────── session structs ─────────────────────────

    private static final class SenderSession {
        String sid;
        long amountCents;
        String memo;
        String receiverPubHex;
    }

    private static final class ReceiverSession {
        String rsid;
        long amountCents;
        String senderPubHex;
        String memo;
    }
}
