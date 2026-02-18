/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.util.Log;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Maintains the peer table for the Circle Mesh network.
 *
 * Tracks discovered peers with their transport, hop count, last-seen time,
 * capabilities and address. Peers not seen for > {@value #PEER_TTL_MS} ms
 * are pruned automatically.
 */
public class PeerManager {

    private static final String TAG = "MeshPeerManager";

    /** Peer considered stale after 60 seconds with no update. */
    private static final long PEER_TTL_MS = 60_000L;

    // ── PeerInfo ─────────────────────────────────────────────────────────────

    public static class PeerInfo {
        public final String      deviceId;       // 8-char hex
        public       String      transport;      // "WIFI_DIRECT" | "MDNS" | "BT_LE" | "USB"
        public       long        lastSeenMs;
        public       int         hops;           // 0 = direct, >0 = via relay
        public       Set<String> capabilities;   // "OTA","MSG","TX","BTL","FILE"
        public       String      address;        // IP or BT address
        public       int         port;
        public       byte[]      publicKeyBytes; // DER-encoded EC public key (may be null)

        public PeerInfo(String deviceId, String transport, String address, int port, int hops) {
            this.deviceId     = deviceId;
            this.transport    = transport;
            this.address      = address;
            this.port         = port;
            this.hops         = hops;
            this.lastSeenMs   = System.currentTimeMillis();
            this.capabilities = Collections.newSetFromMap(new ConcurrentHashMap<>());
        }

        public boolean isDirect() { return hops == 0; }

        public boolean hasCapability(String cap) {
            return capabilities != null && capabilities.contains(cap);
        }

        @Override
        public String toString() {
            return "PeerInfo{id=" + deviceId + ", transport=" + transport
                    + ", hops=" + hops + ", address=" + address + ":" + port
                    + ", caps=" + capabilities + "}";
        }
    }

    // ── Listener ─────────────────────────────────────────────────────────────

    public interface PeerListener {
        void onPeerAdded(PeerInfo peer);
        void onPeerUpdated(PeerInfo peer);
        void onPeerRemoved(String deviceId);
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final ConcurrentHashMap<String, PeerInfo> mPeers     = new ConcurrentHashMap<>();
    private final List<PeerListener>                  mListeners = new ArrayList<>();
    private final ScheduledExecutorService            mPruner;

    // ── Constructor ───────────────────────────────────────────────────────────

    public PeerManager() {
        mPruner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "MeshPeerPruner");
            t.setDaemon(true);
            return t;
        });
        mPruner.scheduleAtFixedRate(this::pruneStale, 30, 30, TimeUnit.SECONDS);
    }

    // ── Peer management ───────────────────────────────────────────────────────

    /**
     * Add or update a peer. Fires onPeerAdded for new peers, onPeerUpdated for existing.
     */
    public void addOrUpdatePeer(PeerInfo peer) {
        if (peer == null || peer.deviceId == null) return;
        boolean isNew = !mPeers.containsKey(peer.deviceId);
        peer.lastSeenMs = System.currentTimeMillis();
        mPeers.put(peer.deviceId, peer);
        Log.d(TAG, (isNew ? "Added" : "Updated") + " peer: " + peer);
        if (isNew) notifyPeerAdded(peer);
        else       notifyPeerUpdated(peer);
    }

    /** Touch last-seen timestamp for a peer (keep-alive). */
    public void touchPeer(String deviceId) {
        PeerInfo peer = mPeers.get(deviceId);
        if (peer != null) peer.lastSeenMs = System.currentTimeMillis();
    }

    /** Remove a peer immediately (explicit disconnect). */
    public void removePeer(String deviceId) {
        PeerInfo removed = mPeers.remove(deviceId);
        if (removed != null) {
            Log.d(TAG, "Removed peer: " + deviceId);
            notifyPeerRemoved(deviceId);
        }
    }

    // ── Routing queries ───────────────────────────────────────────────────────

    /** Get the best route to a device (lowest hop count). Returns null if unknown. */
    public PeerInfo getBestRoute(String deviceId) {
        return mPeers.get(deviceId);
    }

    /** Get a peer by transport address and port. */
    public PeerInfo getPeerByAddress(String address, int port) {
        for (PeerInfo p : mPeers.values()) {
            if (address.equals(p.address) && p.port == port) return p;
        }
        return null;
    }

    /** Get all direct peers (hops == 0). */
    public List<PeerInfo> getDirectPeers() {
        List<PeerInfo> direct = new ArrayList<>();
        for (PeerInfo p : mPeers.values()) {
            if (p.hops == 0) direct.add(p);
        }
        return direct;
    }

    /** Get all known peers. */
    public List<PeerInfo> getAllPeers() {
        return new ArrayList<>(mPeers.values());
    }

    /** Count of currently known peers. */
    public int getPeerCount() { return mPeers.size(); }

    /** Whether a device is in the peer table. */
    public boolean isKnown(String deviceId) { return mPeers.containsKey(deviceId); }

    // ── Pruning ───────────────────────────────────────────────────────────────

    /** Remove all peers not seen within the TTL window. */
    public void pruneStale() {
        long cutoff = System.currentTimeMillis() - PEER_TTL_MS;
        List<String> toRemove = new ArrayList<>();
        for (ConcurrentHashMap.Entry<String, PeerInfo> entry : mPeers.entrySet()) {
            if (entry.getValue().lastSeenMs < cutoff) toRemove.add(entry.getKey());
        }
        for (String id : toRemove) {
            mPeers.remove(id);
            Log.d(TAG, "Pruned stale peer: " + id);
            notifyPeerRemoved(id);
        }
    }

    // ── Listeners ─────────────────────────────────────────────────────────────

    public void addListener(PeerListener listener) {
        synchronized (mListeners) {
            if (!mListeners.contains(listener)) mListeners.add(listener);
        }
    }

    public void removeListener(PeerListener listener) {
        synchronized (mListeners) { mListeners.remove(listener); }
    }

    private void notifyPeerAdded(PeerInfo peer) {
        synchronized (mListeners) {
            for (PeerListener l : mListeners) {
                try { l.onPeerAdded(peer); } catch (Exception e) { Log.w(TAG, "Listener err", e); }
            }
        }
    }

    private void notifyPeerUpdated(PeerInfo peer) {
        synchronized (mListeners) {
            for (PeerListener l : mListeners) {
                try { l.onPeerUpdated(peer); } catch (Exception e) { Log.w(TAG, "Listener err", e); }
            }
        }
    }

    private void notifyPeerRemoved(String deviceId) {
        synchronized (mListeners) {
            for (PeerListener l : mListeners) {
                try { l.onPeerRemoved(deviceId); } catch (Exception e) { Log.w(TAG, "Listener err", e); }
            }
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void shutdown() {
        mPruner.shutdownNow();
        mPeers.clear();
    }
}
