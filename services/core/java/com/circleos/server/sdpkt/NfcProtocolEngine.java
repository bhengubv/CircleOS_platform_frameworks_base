/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.util.Base64;
import android.util.Log;

import za.co.circleos.sdpkt.NfcTransferRequest;
import za.co.circleos.sdpkt.ShongololoTransaction;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * NFC P2P protocol state machine — Phase 1.
 *
 * Implements the SDPKT Titanium handshake protocol over NFC:
 *
 *   SENDER state machine:
 *     IDLE → DISCOVERING → INITIATING → AWAITING_CONFIRM → DONE/FAILED
 *
 *   RECEIVER state machine:
 *     IDLE → ADVERTISING → ACCEPTED → CONFIRMING → DONE/FAILED
 *
 * Transport: NFC HCE (Host Card Emulation) / Reader mode.
 *   The SDPKT Titanium app registers a HostApduService for the SDPKT AID.
 *   This engine handles the application-layer protocol; the NFC layer
 *   (HCE/reader mode) is handled in the vendor app.
 *
 * AID: F0 43 49 52 43 4C 45 53 44 50 (hex for "CIRCLESDP")
 *
 * Message framing (over APDU DATA field):
 *   Byte 0:   message type (MSG_*)
 *   Bytes 1+: JSON payload (UTF-8)
 *
 * Protocol sequence (spec §8.2):
 *   SENDER  → DISCOVER
 *   RECEIVER← ADVERTISE { pubkey, version }
 *   SENDER  → INITIATE  { senderPubkey, amount, nonce }
 *   RECEIVER← ACCEPT    { sessionKey (ECDH) }
 *   SENDER  → TRANSACTION { encrypted tx JSON }
 *   RECEIVER← CONFIRM   { signed receipt }
 *   SENDER  → ACK
 */
public class NfcProtocolEngine {

    private static final String TAG = "SdpktNfc";

    /** SDPKT NFC Application ID (AID) — registered in the SDPKT app HCE manifest. */
    public static final byte[] SDPKT_AID = {
        (byte)0xF0, 0x43, 0x49, 0x52, 0x43, 0x4C, 0x45, 0x53, 0x44, 0x50
    };

    /* ── Message type bytes ─────────────────────────── */
    public static final byte MSG_DISCOVER     = 0x01;
    public static final byte MSG_ADVERTISE    = 0x02;
    public static final byte MSG_INITIATE     = 0x03;
    public static final byte MSG_ACCEPT       = 0x04;
    public static final byte MSG_TRANSACTION  = 0x05;
    public static final byte MSG_CONFIRM      = 0x06;
    public static final byte MSG_ACK          = 0x07;
    public static final byte MSG_DECLINE      = 0x08;
    public static final byte MSG_ERROR        = 0x09;

    /* ── Session states ─────────────────────────────── */
    public static final int STATE_IDLE             = 0;
    public static final int STATE_DISCOVERING      = 1;
    public static final int STATE_INITIATING       = 2;
    public static final int STATE_AWAITING_CONFIRM = 3;
    public static final int STATE_ADVERTISING      = 4;
    public static final int STATE_INCOMING_PENDING = 5;
    public static final int STATE_DONE             = 6;
    public static final int STATE_FAILED           = 7;

    /** An active NFC session (sender or receiver). */
    public static class Session {
        public final String  sessionId;
        public int           state      = STATE_IDLE;
        public boolean       isSender;
        public NfcTransferRequest request;        // sender: outbound request
        public ShongololoTransaction pendingTx;   // both: the in-flight transaction
        public String        peerPubkey;          // the other party's public key
        public String        peerDeviceId;

        Session(String id) { this.sessionId = id; }
    }

    private final TeeKeyManager    mKeyManager;
    private final TransactionSigner mSigner;
    private final NonceCache        mNonceCache;
    private DoubleSpendDetector     mDSD;  // set after construction (Phase 2)

    // active sessions
    private final ConcurrentHashMap<String, Session> mSessions = new ConcurrentHashMap<>();

    public NfcProtocolEngine(TeeKeyManager km, TransactionSigner signer, NonceCache nc) {
        mKeyManager  = km;
        mSigner      = signer;
        mNonceCache  = nc;
    }

    /** Wire in the Phase 2 double-spend detector. */
    public void setDoubleSpendDetector(DoubleSpendDetector dsd) {
        mDSD = dsd;
    }

    /* ── Sender side ─────────────────────────────────── */

    /** Create a sender session. Returns session ID. */
    public String beginSenderSession(NfcTransferRequest request) {
        String id = java.util.UUID.randomUUID().toString();
        Session s = new Session(id);
        s.isSender = true;
        s.request  = request;
        s.state    = STATE_DISCOVERING;
        mSessions.put(id, s);
        Log.d(TAG, "Sender session " + id + " created for " + request.amountCents + " cents");
        return id;
    }

    /**
     * Build the DISCOVER message payload that the sender transmits first.
     * Returns base64-encoded message bytes.
     */
    public String buildDiscoverMessage(String sessionId) {
        Session s = mSessions.get(sessionId);
        if (s == null || !s.isSender) return null;
        String json = "{\"type\":\"discover\",\"version\":1,\"sid\":\"" + sessionId + "\"}";
        return encodeMessage(MSG_DISCOVER, json);
    }

    /* ── Receiver side ───────────────────────────────── */

    /** Create a receiver session when a DISCOVER is received. Returns session ID. */
    public String beginReceiverSession(String incomingBase64) {
        byte[] msg = decodeMessage(incomingBase64);
        if (msg == null || msg[0] != MSG_DISCOVER) return null;

        String id = java.util.UUID.randomUUID().toString();
        Session s = new Session(id);
        s.isSender = false;
        s.state    = STATE_ADVERTISING;
        mSessions.put(id, s);
        Log.d(TAG, "Receiver session " + id + " created");
        return id;
    }

    /**
     * Process an incoming NFC message for a session.
     * Returns the response message to send back (base64), or null if done/error.
     */
    public String processMessage(String sessionId, String incomingBase64) {
        Session s = mSessions.get(sessionId);
        if (s == null) return null;

        byte[] msg = decodeMessage(incomingBase64);
        if (msg == null) return buildError(sessionId, "Malformed message");

        byte msgType = msg[0];
        String json  = msg.length > 1
                ? new String(msg, 1, msg.length - 1, StandardCharsets.UTF_8)
                : "{}";

        Log.d(TAG, "Session " + sessionId + " state=" + s.state + " msg=" + msgType);

        if (s.isSender) {
            return processSenderMessage(s, msgType, json);
        } else {
            return processReceiverMessage(s, msgType, json);
        }
    }

    private String processSenderMessage(Session s, byte msgType, String json) {
        switch (msgType) {
            case MSG_ADVERTISE:
                // Receiver sent us their pubkey → send INITIATE
                s.peerPubkey  = extractJson(json, "pubkey");
                s.peerDeviceId= extractJson(json, "device_id");
                s.state = STATE_INITIATING;
                s.request.recipientPubkey = s.peerPubkey;
                Log.d(TAG, "Peer discovered: " + s.peerDeviceId);
                return buildInitiateMessage(s);

            case MSG_ACCEPT:
                // Receiver accepted → send the signed transaction
                s.state = STATE_AWAITING_CONFIRM;
                return buildTransactionMessage(s);

            case MSG_CONFIRM:
                // Receiver confirmed receipt → send ACK
                s.state = STATE_DONE;
                Log.i(TAG, "Transfer confirmed by receiver: " + s.sessionId);
                return encodeMessage(MSG_ACK, "{\"type\":\"ack\"}");

            case MSG_DECLINE:
                s.state = STATE_FAILED;
                Log.i(TAG, "Transfer declined by receiver");
                return null;

            case MSG_ERROR:
                s.state = STATE_FAILED;
                return null;

            default:
                return buildError(s.sessionId, "Unexpected message " + msgType);
        }
    }

    private String processReceiverMessage(Session s, byte msgType, String json) {
        switch (msgType) {
            case MSG_INITIATE:
                // Sender wants to initiate → send ACCEPT
                s.peerPubkey   = extractJson(json, "sender_pubkey");
                s.peerDeviceId = extractJson(json, "device_id");
                s.state        = STATE_INCOMING_PENDING;
                // Build pending transaction for UI display
                s.pendingTx = buildPendingRx(json, s.peerPubkey);
                Log.d(TAG, "Incoming transfer: " + (s.pendingTx != null ? s.pendingTx.amountCents : "?") + " cents");
                // Return ACCEPT — the app will call acceptIncomingTransfer() to confirm
                return buildAcceptMessage(s);

            case MSG_TRANSACTION:
                // Signed transaction received → verify and send CONFIRM
                return processIncomingTransaction(s, json);

            case MSG_ACK:
                s.state = STATE_DONE;
                return null;

            case MSG_ERROR:
                s.state = STATE_FAILED;
                return null;

            default:
                return buildError(s.sessionId, "Unexpected message " + msgType);
        }
    }

    /** Cancel a session. */
    public void cancelSession(String sessionId) {
        Session s = mSessions.remove(sessionId);
        if (s != null) Log.d(TAG, "Session cancelled: " + sessionId);
    }

    /** Get session state. */
    public Session getSession(String sessionId) {
        return mSessions.get(sessionId);
    }

    /* ── Message builders ────────────────────────────── */

    private String buildInitiateMessage(Session s) {
        String myPubkey   = mKeyManager.getEncodedPublicKey();
        String json = "{\"type\":\"initiate\""
                + ",\"sender_pubkey\":\"" + myPubkey + "\""
                + ",\"device_id\":\"" + deviceId(myPubkey) + "\""
                + ",\"amount\":" + s.request.amountCents
                + ",\"currency\":\"SHG\"}";
        return encodeMessage(MSG_INITIATE, json);
    }

    private String buildAcceptMessage(Session s) {
        String myPubkey = mKeyManager.getEncodedPublicKey();
        String json = "{\"type\":\"accept\""
                + ",\"receiver_pubkey\":\"" + myPubkey + "\""
                + ",\"device_id\":\"" + deviceId(myPubkey) + "\"}";
        return encodeMessage(MSG_ACCEPT, json);
    }

    private String buildTransactionMessage(Session s) {
        ShongololoTransaction tx = mSigner.buildAndSign(
                s.request.amountCents,
                s.peerPubkey,
                s.request.memo);
        if (tx == null) {
            s.state = STATE_FAILED;
            return buildError(s.sessionId, "Signing failed");
        }
        s.pendingTx = tx;
        String json = txToJson(tx);
        return encodeMessage(MSG_TRANSACTION, json);
    }

    private String processIncomingTransaction(Session s, String json) {
        ShongololoTransaction tx = jsonToTx(json);
        if (tx == null) return buildError(s.sessionId, "Malformed transaction");

        // Phase 2: full double-spend + replay + rate-limit check
        if (mDSD != null) {
            int dsdResult = mDSD.check(tx);
            if (dsdResult != DoubleSpendDetector.OK) {
                s.state = STATE_FAILED;
                Log.w(TAG, "DSD rejected tx: " + DoubleSpendDetector.describe(dsdResult));
                return buildError(s.sessionId, "Rejected: " + DoubleSpendDetector.describe(dsdResult));
            }
        } else {
            // Phase 1 fallback: basic signature + replay check only
            int verifyResult = mSigner.verify(tx, mNonceCache);
            if (verifyResult != TransactionSigner.VERIFY_OK) {
                s.state = STATE_FAILED;
                return buildError(s.sessionId, "Verification failed: " + verifyResult);
            }
        }

        s.pendingTx = tx;
        s.pendingTx.type = ShongololoTransaction.TYPE_RECEIVE;

        // Build signed receipt
        String myPubkey = mKeyManager.getEncodedPublicKey();
        String receiptPayload = (tx.txId + "|confirmed|" + System.currentTimeMillis())
                .getBytes(StandardCharsets.UTF_8).toString();
        String sig = mKeyManager.sign(
                (tx.txId + "|confirmed|" + System.currentTimeMillis())
                        .getBytes(StandardCharsets.UTF_8));

        String confirmJson = "{\"type\":\"confirm\""
                + ",\"tx_id\":\"" + tx.txId + "\""
                + ",\"receiver_pubkey\":\"" + myPubkey + "\""
                + ",\"sig\":\"" + (sig != null ? sig : "") + "\"}";
        s.state = STATE_DONE;
        Log.i(TAG, "Incoming tx " + tx.txId + " verified — sending CONFIRM");
        return encodeMessage(MSG_CONFIRM, confirmJson);
    }

    private String buildError(String sessionId, String reason) {
        Log.w(TAG, "NFC error [" + sessionId + "]: " + reason);
        return encodeMessage(MSG_ERROR,
                "{\"type\":\"error\",\"reason\":\"" + reason + "\"}");
    }

    /* ── Encoding helpers ────────────────────────────── */

    private String encodeMessage(byte type, String json) {
        byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8);
        byte[] msg = new byte[1 + jsonBytes.length];
        msg[0] = type;
        System.arraycopy(jsonBytes, 0, msg, 1, jsonBytes.length);
        return Base64.encodeToString(msg, Base64.NO_WRAP);
    }

    private byte[] decodeMessage(String base64) {
        try { return Base64.decode(base64, Base64.NO_WRAP); }
        catch (Exception e) { return null; }
    }

    private String extractJson(String json, String key) {
        String marker = "\"" + key + "\":\"";
        int start = json.indexOf(marker);
        if (start < 0) return "";
        start += marker.length();
        int end = json.indexOf("\"", start);
        return end > start ? json.substring(start, end) : "";
    }

    private String txToJson(ShongololoTransaction tx) {
        return "{\"version\":1,\"type\":\"transfer\""
                + ",\"id\":\"" + tx.txId + "\""
                + ",\"timestamp\":" + tx.createdAtMs
                + ",\"nonce\":\"" + tx.nonce + "\""
                + ",\"sender_pubkey\":\"" + tx.senderPubkey + "\""
                + ",\"sender_device_id\":\"" + tx.senderDeviceId + "\""
                + ",\"receiver_pubkey\":\"" + tx.receiverPubkey + "\""
                + ",\"amount\":" + tx.amountCents
                + ",\"currency\":\"" + tx.currency + "\""
                + ",\"signature\":\"" + tx.signature + "\""
                + ",\"memo\":\"" + (tx.memo != null ? tx.memo : "") + "\"}";
    }

    private ShongololoTransaction jsonToTx(String json) {
        try {
            ShongololoTransaction tx = new ShongololoTransaction();
            tx.txId           = extractJson(json, "id");
            tx.createdAtMs    = jsonLong(json, "timestamp");
            tx.nonce          = extractJson(json, "nonce");
            tx.senderPubkey   = extractJson(json, "sender_pubkey");
            tx.senderDeviceId = extractJson(json, "sender_device_id");
            tx.receiverPubkey = extractJson(json, "receiver_pubkey");
            tx.amountCents    = jsonLong(json, "amount");
            tx.currency       = extractJson(json, "currency");
            tx.signature      = extractJson(json, "signature");
            tx.memo           = extractJson(json, "memo");
            if (tx.txId.isEmpty() || tx.signature.isEmpty()) return null;
            return tx;
        } catch (Exception e) {
            return null;
        }
    }

    private ShongololoTransaction buildPendingRx(String json, String senderPubkey) {
        ShongololoTransaction tx = new ShongololoTransaction();
        tx.type          = ShongololoTransaction.TYPE_RECEIVE;
        tx.status        = ShongololoTransaction.STATUS_PENDING_SETTLEMENT;
        tx.amountCents   = jsonLong(json, "amount");
        tx.senderPubkey  = senderPubkey;
        tx.currency      = "SHG";
        return tx;
    }

    private long jsonLong(String json, String key) {
        String marker = "\"" + key + "\":";
        int idx = json.indexOf(marker);
        if (idx < 0) return 0;
        idx += marker.length();
        int end = idx;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        try { return Long.parseLong(json.substring(idx, end)); } catch (Exception e) { return 0; }
    }

    private String deviceId(String encodedPubkey) {
        try {
            byte[] bytes = Base64.decode(encodedPubkey, Base64.NO_WRAP);
            return TeeKeyManager.sha256Hex(bytes);
        } catch (Exception e) { return "unknown"; }
    }
}
