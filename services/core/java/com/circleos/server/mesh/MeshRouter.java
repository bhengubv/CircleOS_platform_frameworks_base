/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.util.Log;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Routing logic for the Circle Mesh Network.
 *
 * <h3>Routing modes</h3>
 * <ul>
 *   <li><b>Direct</b>: Recipient is a known direct peer (hops == 0) — frame
 *       is sent via the peer's transport connection.</li>
 *   <li><b>Relay</b>: Recipient is known but reachable only via one or more
 *       intermediate peers. The frame is forwarded to the best-route peer
 *       with TTL decremented.</li>
 *   <li><b>Flood</b>: Recipient is unknown — frame is forwarded to all direct
 *       peers with TTL decremented (store-and-forward model).</li>
 * </ul>
 *
 * <h3>Loop prevention</h3>
 * Incoming frames are de-duplicated using an LRU cache of 1 000 message IDs.
 * A frame whose message ID is already in the cache is silently dropped.
 *
 * <h3>TTL management</h3>
 * Relay and flood paths decrement TTL by 1 before forwarding. Frames with
 * TTL == 0 are never forwarded.
 *
 * <h3>Transport abstraction</h3>
 * The router interacts with peers via {@link PeerManager} and delegates actual
 * frame transmission to a {@link TransportSender} callback supplied by
 * {@link CircleMeshService}.
 */
public class MeshRouter {

    private static final String TAG = "MeshRouter";

    /** Maximum number of message IDs kept in the deduplication LRU cache. */
    private static final int DEDUP_CACHE_SIZE = 1_000;

    // ── Callback interfaces ───────────────────────────────────────────────────

    /**
     * Delivered when a routed frame arrives at the local device (final recipient).
     */
    public interface MessageDeliveryListener {
        /**
         * @param msg  Decoded mesh message.
         * @param from Transport address of the immediate sender.
         */
        void onMessageDelivered(MeshProtocol.Message msg, String from);
    }

    /**
     * Sends a frame via whatever transport is best for the given peer.
     * Implemented by {@link CircleMeshService}.
     */
    public interface TransportSender {
        /**
         * @param peer  Peer to send to.
         * @param frame Encoded mesh frame.
         * @return true if the frame was handed off to a transport.
         */
        boolean sendToPeer(PeerManager.PeerInfo peer, byte[] frame);
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final String              mLocalDeviceId;
    private final PeerManager         mPeerManager;
    private TransportSender           mSender;
    private MessageDeliveryListener   mDeliveryListener;

    /** LRU cache for deduplication. Access is synchronized. */
    private final Map<String, Boolean> mSeenIds =
            Collections.synchronizedMap(new LinkedHashMap<String, Boolean>(
                    DEDUP_CACHE_SIZE + 1, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                    return size() > DEDUP_CACHE_SIZE;
                }
            });

    // ── Constructor ───────────────────────────────────────────────────────────

    /**
     * @param localDeviceId This device's current 16-char hex ID.
     * @param peerManager   The shared peer table.
     */
    public MeshRouter(String localDeviceId, PeerManager peerManager) {
        mLocalDeviceId = localDeviceId;
        mPeerManager   = peerManager;
    }

    public void setSender(TransportSender sender) {
        mSender = sender;
    }

    public void setDeliveryListener(MessageDeliveryListener listener) {
        mDeliveryListener = listener;
    }

    // ── Outbound routing ──────────────────────────────────────────────────────

    /**
     * Routes an outbound frame to the specified recipient device.
     *
     * <ol>
     *   <li>Look up recipient in peer table.</li>
     *   <li>If found and direct → send directly.</li>
     *   <li>If found but relayed → forward to the best-route peer (decrement TTL).</li>
     *   <li>If not found → flood to all direct peers (decrement TTL).</li>
     * </ol>
     *
     * @param recipientDeviceId 16-char hex target device ID.
     * @param frame             Fully encoded mesh frame (TTL must be set correctly by caller).
     * @return true if the frame was dispatched to at least one peer.
     */
    public boolean route(String recipientDeviceId, byte[] frame) {
        if (mSender == null) {
            Log.e(TAG, "route(): no TransportSender set");
            return false;
        }

        // Check for broadcast
        if (isBroadcastId(recipientDeviceId)) {
            return flood(frame, null);
        }

        // Direct or relay
        PeerManager.PeerInfo peer = mPeerManager.getBestRoute(recipientDeviceId);
        if (peer != null) {
            if (peer.isDirect()) {
                Log.d(TAG, "route(): direct to " + recipientDeviceId);
                return mSender.sendToPeer(peer, frame);
            } else {
                Log.d(TAG, "route(): relay via " + peer.address + " to " + recipientDeviceId);
                byte[] relayFrame = decrementTtl(frame);
                return relayFrame != null && mSender.sendToPeer(peer, relayFrame);
            }
        }

        // Unknown destination — flood
        Log.d(TAG, "route(): unknown recipient " + recipientDeviceId + " — flooding");
        return flood(decrementTtl(frame), null);
    }

    // ── Inbound handling ──────────────────────────────────────────────────────

    /**
     * Processes an inbound frame received from a transport layer.
     *
     * <ol>
     *   <li>Decode the frame.</li>
     *   <li>De-duplicate by message ID (LRU cache).</li>
     *   <li>Update peer table from sender info.</li>
     *   <li>If addressed to us → deliver to listener.</li>
     *   <li>If addressed to someone else → re-route (relay/flood).</li>
     * </ol>
     *
     * @param frame     Raw encoded frame bytes.
     * @param fromAddr  Transport-layer address of the immediate sender.
     * @param transport Transport type (TYPE_* constant).
     */
    public void handleIncoming(byte[] frame, String fromAddr, String transport) {
        MeshProtocol.Message msg;
        try {
            msg = MeshProtocol.decode(frame);
        } catch (IllegalArgumentException e) {
            Log.w(TAG, "handleIncoming: decode failed from " + fromAddr + ": " + e.getMessage());
            return;
        }

        // Deduplication
        String uuid = msg.getMessageUuid();
        if (mSeenIds.containsKey(uuid)) {
            Log.d(TAG, "handleIncoming: duplicate msgId=" + uuid + " dropped");
            return;
        }
        mSeenIds.put(uuid, Boolean.TRUE);

        // Update peer table from sender
        updatePeerFromIncoming(msg, fromAddr, transport);

        String recipientId = bytesToHex(msg.recipientId);

        // Is this message for us?
        if (mLocalDeviceId.equalsIgnoreCase(recipientId) || isBroadcastId(recipientId)) {
            Log.d(TAG, "handleIncoming: delivering type=0x"
                    + Integer.toHexString(msg.type) + " from " + msg.getSenderHex());
            if (mDeliveryListener != null) {
                mDeliveryListener.onMessageDelivered(msg, fromAddr);
            }
            // Broadcasts are also forwarded
            if (isBroadcastId(recipientId) && msg.ttl > 1) {
                byte[] fwd = decrementTtl(frame);
                if (fwd != null) flood(fwd, fromAddr);
            }
            return;
        }

        // Not for us — relay if TTL permits
        if (msg.ttl <= 1) {
            Log.d(TAG, "handleIncoming: TTL exhausted, dropping");
            return;
        }

        Log.d(TAG, "handleIncoming: relaying to " + recipientId);
        byte[] relayFrame = decrementTtl(frame);
        if (relayFrame != null) {
            route(recipientId, relayFrame);
        }
    }

    // ── Flood ─────────────────────────────────────────────────────────────────

    /**
     * Sends the frame to all direct peers (hops == 0), optionally excluding
     * one peer (to avoid sending back where it came from).
     *
     * @param frame   Frame to flood (TTL already decremented by caller).
     * @param exclude Transport address to skip (may be null).
     * @return true if at least one peer was reached.
     */
    private boolean flood(byte[] frame, String exclude) {
        if (frame == null) return false;
        List<PeerManager.PeerInfo> direct = mPeerManager.getDirectPeers();
        if (direct.isEmpty()) return false;

        boolean sent = false;
        for (PeerManager.PeerInfo peer : direct) {
            String addr = peer.address + ":" + peer.port;
            if (addr.equals(exclude)) continue;
            if (mSender != null && mSender.sendToPeer(peer, frame)) {
                sent = true;
            }
        }
        return sent;
    }

    // ── Peer table update ─────────────────────────────────────────────────────

    /**
     * Auto-updates the peer table when we receive an inbound frame. This gives
     * us free topology information with every message we receive.
     */
    private void updatePeerFromIncoming(MeshProtocol.Message msg,
            String fromAddr, String transport) {
        String senderId = msg.getSenderHex();
        if (senderId == null || senderId.isEmpty()) return;

        // Parse address and port from "ip:port" format
        String address = fromAddr;
        int port = 0;
        int colonIdx = fromAddr.lastIndexOf(':');
        if (colonIdx > 0) {
            address = fromAddr.substring(0, colonIdx);
            try { port = Integer.parseInt(fromAddr.substring(colonIdx + 1)); }
            catch (NumberFormatException ignored) {}
        }

        PeerManager.PeerInfo existing = mPeerManager.getBestRoute(senderId);
        if (existing != null) {
            // Just touch the timestamp
            mPeerManager.touchPeer(senderId);
        } else {
            // Add as a new direct peer (hops = 0 since we received from them directly)
            PeerManager.PeerInfo peer = new PeerManager.PeerInfo(
                    senderId, transport, address, port, 0);
            mPeerManager.addOrUpdatePeer(peer);
        }
    }

    // ── TTL manipulation ──────────────────────────────────────────────────────

    /**
     * Returns a copy of the frame with TTL decremented by 1.
     * Returns null if the frame is too short or TTL is already 0.
     */
    private static byte[] decrementTtl(byte[] frame) {
        if (frame == null || frame.length < MeshProtocol.HEADER_SIZE) return null;
        // TTL is at byte offset 5 in the header (magic[2] + version[1] + type[1] + flags[1] = 5)
        int ttlOffset = 5;
        int ttl = frame[ttlOffset] & 0xFF;
        if (ttl == 0) return null;
        byte[] copy = frame.clone();
        copy[ttlOffset] = (byte) (ttl - 1);
        return copy;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean isBroadcastId(String id) {
        if (id == null) return false;
        // All-zeroes device ID is treated as broadcast
        return id.matches("0{16}") || id.equalsIgnoreCase("ffffffffffffffff");
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        return MeshCrypto.bytesToHex(bytes);
    }
}
