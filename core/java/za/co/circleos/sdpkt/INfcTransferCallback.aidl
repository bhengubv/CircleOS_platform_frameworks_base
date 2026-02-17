/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import za.co.circleos.sdpkt.TransactionResult;
import za.co.circleos.sdpkt.ShongololoTransaction;

/**
 * Callback for NFC transfer events — delivered to the SDPKT app.
 * All methods are oneway (non-blocking fire-and-forget).
 */
oneway interface INfcTransferCallback {
    /** Transfer completed successfully. */
    void onTransferComplete(in TransactionResult result);

    /** Transfer failed. */
    void onTransferFailed(int errorCode, String message);

    /** Peer device discovered in NFC field. */
    void onPeerDiscovered(String peerDeviceId);

    /** Peer device left NFC field. */
    void onPeerLost();

    /**
     * Incoming transfer is waiting for user confirmation.
     * App should show the accept/decline UI.
     */
    void onIncomingTransfer(String sessionId, in ShongololoTransaction pendingTx);
}
