/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import za.co.circleos.sdpkt.WalletKey;
import za.co.circleos.sdpkt.WalletBalance;
import za.co.circleos.sdpkt.ShongololoTransaction;
import za.co.circleos.sdpkt.TransactionResult;
import za.co.circleos.sdpkt.NfcTransferRequest;
import za.co.circleos.sdpkt.INfcTransferCallback;
import za.co.circleos.sdpkt.SyncStatus;

/**
 * SDPKT Titanium wallet binder interface.
 *
 * Normal operations (getBalance, getTransactions) require ACCESS_SDPKT (normal).
 * Transfer operations require user biometric/PIN confirmation inside the TEE.
 * Administrative operations require MANAGE_SDPKT (signature).
 *
 * Service name: "circle.sdpkt"
 */
interface IShongololoWallet {

    /* ── Wallet lifecycle ────────────────────────────── */

    /** True if wallet has been initialized (keypair generated in TEE). */
    boolean hasWallet();

    /**
     * Generate a new ECDSA keypair in the TEE and initialize the wallet.
     * Returns false if already initialized or TEE unavailable.
     */
    boolean initializeWallet();

    /** Return the wallet's public key and address. Null if not initialized. */
    WalletKey getWalletKey();

    /* ── Balance ─────────────────────────────────────── */

    /** Current balance snapshot. */
    WalletBalance getBalance();

    /* ── NFC transfer session ────────────────────────── */

    /**
     * Begin an NFC transfer session as SENDER.
     * Returns a session ID. The NFC app uses processNfcMessage() to drive
     * the handshake state machine as NFC messages arrive from the peer.
     */
    String beginNfcSession(in NfcTransferRequest request);

    /**
     * Process an incoming NFC message for an active session.
     * Returns the response payload to send back to the peer (base64),
     * or null if the session is complete or failed.
     */
    String processNfcMessage(String sessionId, String incomingBase64);

    /** Cancel an in-progress NFC session. */
    void cancelNfcSession(String sessionId);

    /**
     * Accept an incoming transfer request (called by receiver after showing UI).
     * Returns the signed receipt to send back to the sender.
     */
    TransactionResult acceptIncomingTransfer(String sessionId);

    /** Decline an incoming transfer. */
    void declineIncomingTransfer(String sessionId);

    /* ── Transaction history ─────────────────────────── */

    /**
     * List transactions, newest first.
     * @param maxResults 0 = all
     * @param sinceEpochMs 0 = all time
     */
    List<ShongololoTransaction> getTransactions(int maxResults, long sinceEpochMs);

    /** Retrieve a specific transaction by ID. */
    ShongololoTransaction getTransaction(String txId);

    /* ── Limits ──────────────────────────────────────── */

    /** Effective per-tap limit in cents (affected by location/mode/protection). */
    long getPerTapLimitCents();

    /** Remaining daily allowance in cents. */
    long getDailyRemainingCents();

    /** Total offline spending since last sync, in cents. */
    long getOfflineAccumulationCents();

    /* ── Settlement sync (Phase 2) ───────────────────────── */

    /**
     * All outbound transactions awaiting settlement (PENDING_SETTLEMENT status).
     * Newest-first.
     */
    List<ShongololoTransaction> getPendingTransactions();

    /** Current sync state snapshot. */
    SyncStatus getSyncStatus();

    /**
     * Trigger immediate settlement drain if network is available.
     * No-op if offline.
     */
    void forceSyncNow();

    /** Number of outbound transactions not yet settled. */
    int getPendingCount();

    /* ── Service info ────────────────────────────────── */

    int getServiceVersion();
}
