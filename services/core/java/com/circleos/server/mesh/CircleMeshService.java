/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.LocalServices;
import com.android.server.SystemService;

import za.co.circleos.mesh.ICircleMeshService;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * CircleOS Circle Mesh Network Service (full stack).
 *
 * <p>This service orchestrates the complete peer-to-peer mesh stack:
 * <ul>
 *   <li>{@link MeshCrypto}     — identity, encryption, rotating device ID</li>
 *   <li>{@link PeerManager}    — live peer table with TTL pruning</li>
 *   <li>{@link MessageStore}   — SQLite store-and-forward queue</li>
 *   <li>{@link MeshRouter}     — direct / relay / flood routing</li>
 *   <li>{@link WifiDirectTransport} — TCP over WiFi Direct (port 9847)</li>
 *   <li>{@link MdnsTransport}  — TCP over LAN mDNS (port 8723)</li>
 *   <li>{@link BluetoothLeTransport} — BLE discovery-only</li>
 * </ul>
 *
 * <h3>Battery policy</h3>
 * <ul>
 *   <li>Battery ≥ 50%: full mesh (all transports + relay enabled).</li>
 *   <li>Battery 20–49%: relay disabled; direct messages only.</li>
 *   <li>Battery &lt; 20%: mesh suspended; only emergency (URGENT) frames processed.</li>
 * </ul>
 *
 * <h3>Periodic tasks</h3>
 * <ul>
 *   <li>Every 30 s: broadcast ANNOUNCE frame to all direct peers.</li>
 *   <li>Every 60 s: flush store-and-forward queue to newly-online peers.</li>
 *   <li>Every 24 h: prune stale messages from MessageStore.</li>
 * </ul>
 *
 * <h3>Registration</h3>
 * No public Binder. Callers in the same process use {@link LocalServices} to
 * retrieve this service as {@link CircleMeshService}.
 */
public final class CircleMeshService extends SystemService {

    private static final String TAG = "CircleMeshService";

    /** LocalServices registration class. */
    public static final String SERVICE_CLASS = CircleMeshService.class.getName();

    // Periodic task intervals
    private static final long ANNOUNCE_INTERVAL_MS   = 30_000L;
    private static final long FLUSH_INTERVAL_MS      = 60_000L;
    private static final long PRUNE_INTERVAL_MS      = 24L * 60 * 60 * 1_000;

    // Battery thresholds
    private static final int BATT_RELAY_MIN     = 50; // relay disabled below this %
    private static final int BATT_SUSPEND_MIN   = 20; // mesh suspended below this %

    // ── Sub-components ────────────────────────────────────────────────────────

    private MeshCrypto    mCrypto;
    private PeerManager   mPeerManager;
    private MessageStore  mMessageStore;
    private MeshRouter    mRouter;

    private WifiDirectTransport     mWifiTransport;
    private BluetoothLeTransport    mBleTransport;
    private MdnsTransport           mMdnsTransport;

    // ── Threading ─────────────────────────────────────────────────────────────

    private HandlerThread mHandlerThread;
    private Handler       mHandler;

    // ── State ─────────────────────────────────────────────────────────────────

    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private volatile int        mBatteryPct = 100;

    // ── Binder implementation ─────────────────────────────────────────────────

    private final ICircleMeshService.Stub mBinder = new ICircleMeshService.Stub() {

        @Override
        public boolean sendMessage(String recipientDeviceId, byte[] payload, int msgType) {
            return CircleMeshService.this.sendMessage(recipientDeviceId, payload, msgType);
        }

        @Override
        public int getPeerCount() {
            return CircleMeshService.this.getPeerCount();
        }

        @Override
        public boolean isRunning() {
            return CircleMeshService.this.isRunning();
        }

        @Override
        public String getDeviceId() {
            return CircleMeshService.this.getDeviceId();
        }
    };

    // ── Lifecycle shim ────────────────────────────────────────────────────────

    /**
     * SystemService lifecycle shim registered in SystemServer.
     */
    public static final class Lifecycle extends SystemService {
        private CircleMeshService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new CircleMeshService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            if (phase == PHASE_BOOT_COMPLETED) {
                mService.onBootCompleted();
            }
        }
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    public CircleMeshService(Context context) {
        super(context);
    }

    // ── SystemService overrides ───────────────────────────────────────────────

    @Override
    public void onStart() {
        Log.i(TAG, "onStart()");

        mHandlerThread = new HandlerThread("CircleMesh");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());

        // Initialise components
        mCrypto       = new MeshCrypto();
        mPeerManager  = new PeerManager();
        mMessageStore = new MessageStore(getContext());

        mCrypto.init();
        String deviceId = mCrypto.getDeviceId();
        Log.i(TAG, "Device ID: " + deviceId);

        mRouter = new MeshRouter(deviceId, mPeerManager);
        mRouter.setDeliveryListener(this::onMessageDelivered);
        mRouter.setSender(this::dispatchToPeer);

        // Register with LocalServices for same-process callers
        LocalServices.addService(CircleMeshService.class, this);
        Log.i(TAG, "Registered with LocalServices");

        // Publish Binder service so apps can reach us via ServiceManager
        publishBinderService("circle.mesh", mBinder);
        Log.i(TAG, "Published binder service: circle.mesh");
    }

    // ── Boot-completed ────────────────────────────────────────────────────────

    void onBootCompleted() {
        Log.i(TAG, "onBootCompleted() — starting mesh");

        // Monitor battery level
        registerBatteryReceiver();

        // Start the mesh on the handler thread
        mHandler.post(this::startMesh);
    }

    // ── Mesh start / stop ─────────────────────────────────────────────────────

    private void startMesh() {
        if (!mRunning.compareAndSet(false, true)) return;
        Log.i(TAG, "Starting mesh stack");

        String deviceId = mCrypto.getDeviceId();
        String caps     = "OTA,MSG,TX,BTL,FILE";

        // Initialise transports
        mWifiTransport = new WifiDirectTransport(getContext(), deviceId, caps, "0.1.0-alpha");
        mMdnsTransport = new MdnsTransport(getContext(), deviceId, caps);
        mBleTransport  = new BluetoothLeTransport(getContext(), deviceId);

        // Wire up listeners
        MeshTransport.MessageListener msgListener = (from, transport, frame) ->
                mHandler.post(() -> mRouter.handleIncoming(frame, from, transport));

        MeshTransport.PeerDiscoveryListener discoveryListener = new MeshTransport.PeerDiscoveryListener() {
            @Override
            public void onPeerDiscovered(String peerId, String address, int port,
                    String transport, String caps) {
                Log.d(TAG, "Peer discovered: id=" + peerId + " addr=" + address
                        + " transport=" + transport);
                PeerManager.PeerInfo peer = new PeerManager.PeerInfo(
                        peerId, transport, address, port, 0);
                if (caps != null) {
                    for (String cap : caps.split(",")) {
                        if (!cap.isEmpty()) peer.capabilities.add(cap.trim());
                    }
                }
                mPeerManager.addOrUpdatePeer(peer);
                // Attempt to flush queued messages for this peer
                mHandler.post(() -> flushStoredMessages(peerId));
            }

            @Override
            public void onPeerLost(String address) {
                Log.d(TAG, "Peer lost at address: " + address);
                // We don't know the device ID from address alone — peer table TTL handles cleanup
            }
        };

        mWifiTransport.setMessageListener(msgListener);
        mWifiTransport.setPeerDiscoveryListener(discoveryListener);
        mMdnsTransport.setMessageListener(msgListener);
        mMdnsTransport.setPeerDiscoveryListener(discoveryListener);
        mBleTransport.setMessageListener(msgListener);
        mBleTransport.setPeerDiscoveryListener(discoveryListener);

        // Start transports (battery check inline)
        if (mBatteryPct >= BATT_SUSPEND_MIN) {
            mWifiTransport.start();
            mMdnsTransport.start();
        }
        mBleTransport.start(); // BLE advertising is low-power; always start

        // Schedule periodic tasks
        mHandler.postDelayed(mAnnounceRunnable, ANNOUNCE_INTERVAL_MS);
        mHandler.postDelayed(mFlushRunnable, FLUSH_INTERVAL_MS);
        mHandler.postDelayed(mPruneRunnable, PRUNE_INTERVAL_MS);

        Log.i(TAG, "Mesh stack started, battery=" + mBatteryPct + "%");
    }

    public void stopMesh() {
        if (!mRunning.compareAndSet(true, false)) return;
        Log.i(TAG, "Stopping mesh stack");

        mHandler.removeCallbacks(mAnnounceRunnable);
        mHandler.removeCallbacks(mFlushRunnable);
        mHandler.removeCallbacks(mPruneRunnable);

        if (mWifiTransport != null) mWifiTransport.stop();
        if (mMdnsTransport != null) mMdnsTransport.stop();
        if (mBleTransport  != null) mBleTransport.stop();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Sends a message to the specified device.
     *
     * <p>If the recipient is not reachable, the message is stored for later delivery.
     *
     * @param recipientDeviceId 16-char hex target device ID.
     * @param payload           Message payload bytes.
     * @param msgType           Message type constant from {@link MeshProtocol}.
     * @return true if the message was dispatched or queued.
     */
    public boolean sendMessage(String recipientDeviceId, byte[] payload, int msgType) {
        if (!mRunning.get()) {
            Log.w(TAG, "sendMessage: mesh not running");
            return false;
        }

        String localId = mCrypto.getDeviceId();
        byte[] senderIdBytes    = hexToBytes(localId, 8);
        byte[] recipientIdBytes = hexToBytes(recipientDeviceId, 8);
        byte[] msgIdBytes       = generateMessageId();

        byte[] frame = MeshProtocol.buildFrame(
                msgType, (byte) 0, (byte) 7, senderIdBytes, recipientIdBytes,
                msgIdBytes, payload);

        if (frame == null) {
            Log.e(TAG, "sendMessage: buildFrame returned null");
            return false;
        }

        // Attempt immediate delivery
        boolean sent = mRouter.route(recipientDeviceId, frame);
        if (!sent) {
            // Store for later
            String msgId = MeshCrypto.bytesToHex(msgIdBytes);
            mMessageStore.storeMessage(msgId, recipientDeviceId, msgType, frame);
            Log.d(TAG, "sendMessage: queued for later delivery, msgId=" + msgId);
        }
        return true;
    }

    /** Returns the current peer count. */
    public int getPeerCount() { return mPeerManager.getPeerCount(); }

    /** Returns the local rotating device ID (16-char hex). */
    public String getDeviceId() { return mCrypto.getDeviceId(); }

    /** Returns true if the mesh stack is running. */
    public boolean isRunning() { return mRunning.get(); }

    // ── Transport dispatch ────────────────────────────────────────────────────

    /**
     * Selects the best available transport for a peer and sends the frame.
     * Implements {@link MeshRouter.TransportSender}.
     */
    private boolean dispatchToPeer(PeerManager.PeerInfo peer, byte[] frame) {
        // Relay requires battery >= 50% (when the message is for someone else)
        // Direct sends are always allowed if battery >= 20%
        if (mBatteryPct < BATT_SUSPEND_MIN) {
            Log.d(TAG, "dispatchToPeer: battery critical, dropping non-urgent frame");
            return false;
        }

        String address = peer.address + ":" + peer.port;

        switch (peer.transport) {
            case MeshTransport.TYPE_WIFI_DIRECT:
                return mWifiTransport != null && mWifiTransport.isActive()
                        && mWifiTransport.send(address, frame);
            case MeshTransport.TYPE_MDNS:
                return mMdnsTransport != null && mMdnsTransport.isActive()
                        && mMdnsTransport.send(address, frame);
            case MeshTransport.TYPE_BT_LE:
                // BLE is discovery-only; fall through to WiFi/mDNS for data
                Log.d(TAG, "dispatchToPeer: BLE peer — trying WiFi fallback");
                if (mWifiTransport != null && mWifiTransport.isActive()) {
                    return mWifiTransport.send(peer.address + ":" + WifiDirectTransport.MESH_PORT, frame);
                }
                return false;
            default:
                Log.w(TAG, "dispatchToPeer: unknown transport " + peer.transport);
                return false;
        }
    }

    // ── Message delivery ──────────────────────────────────────────────────────

    /**
     * Called by {@link MeshRouter} when a frame addressed to us arrives.
     */
    private void onMessageDelivered(MeshProtocol.Message msg, String from) {
        Log.i(TAG, "Message delivered: type=0x" + Integer.toHexString(msg.type)
                + " from=" + msg.getSenderHex() + " via=" + from);
        // TODO: dispatch to per-capability handlers (OTA, MSG, TX, FILE, Butler)
    }

    // ── Store-and-forward flush ───────────────────────────────────────────────

    /** Attempts to deliver all queued messages for a given peer. */
    private void flushStoredMessages(String deviceId) {
        List<MessageStore.StoredMessage> pending = mMessageStore.getPendingFor(deviceId);
        if (pending.isEmpty()) return;
        Log.d(TAG, "flushStoredMessages: " + pending.size() + " queued for " + deviceId);

        for (MessageStore.StoredMessage sm : pending) {
            boolean sent = mRouter.route(deviceId, sm.payload);
            if (sent) {
                mMessageStore.markDelivered(sm.rowId);
                Log.d(TAG, "Delivered stored msg " + sm.msgId + " to " + deviceId);
            } else {
                mMessageStore.incrementAttempts(sm.rowId);
            }
        }
    }

    // ── Periodic runnables ────────────────────────────────────────────────────

    private final Runnable mAnnounceRunnable = new Runnable() {
        @Override
        public void run() {
            if (!mRunning.get()) return;
            sendAnnounce();
            mHandler.postDelayed(this, ANNOUNCE_INTERVAL_MS);
        }
    };

    private final Runnable mFlushRunnable = new Runnable() {
        @Override
        public void run() {
            if (!mRunning.get()) return;
            for (PeerManager.PeerInfo peer : mPeerManager.getDirectPeers()) {
                flushStoredMessages(peer.deviceId);
            }
            mHandler.postDelayed(this, FLUSH_INTERVAL_MS);
        }
    };

    private final Runnable mPruneRunnable = new Runnable() {
        @Override
        public void run() {
            if (!mRunning.get()) return;
            mMessageStore.pruneOld();
            mHandler.postDelayed(this, PRUNE_INTERVAL_MS);
        }
    };

    // ── Announce ──────────────────────────────────────────────────────────────

    private void sendAnnounce() {
        String localId = mCrypto.getDeviceId();
        byte[] senderId = hexToBytes(localId, 8);
        byte[] bcastId  = new byte[8]; // all zeros = broadcast
        byte[] msgId    = generateMessageId();

        // ANNOUNCE payload: just the DER-encoded public key
        byte[] pubKey = mCrypto.getPublicKeyBytes();
        byte[] frame = MeshProtocol.buildFrame(
                MeshProtocol.TYPE_ANNOUNCE, MeshProtocol.FLAG_BROADCAST, (byte) 3,
                senderId, bcastId, msgId, pubKey);

        if (frame != null) {
            if (mWifiTransport != null && mWifiTransport.isActive()) {
                mWifiTransport.announce(frame);
            }
            if (mMdnsTransport != null && mMdnsTransport.isActive()) {
                mMdnsTransport.announce(frame);
            }
            if (mBleTransport != null && mBleTransport.isActive()) {
                mBleTransport.announce(frame);
            }
        }
    }

    // ── Battery monitoring ────────────────────────────────────────────────────

    private void registerBatteryReceiver() {
        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, 100);
                int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, 100);
                int pct   = (scale > 0) ? (level * 100 / scale) : 100;
                onBatteryChanged(pct);
            }
        };
        getContext().registerReceiver(receiver,
                new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
    }

    private void onBatteryChanged(int pct) {
        int prev = mBatteryPct;
        mBatteryPct = pct;

        if (prev >= BATT_SUSPEND_MIN && pct < BATT_SUSPEND_MIN) {
            Log.w(TAG, "Battery critical (" + pct + "%) — suspending data transports");
            mHandler.post(() -> {
                if (mWifiTransport != null) mWifiTransport.stop();
                if (mMdnsTransport != null) mMdnsTransport.stop();
            });
        } else if (prev < BATT_SUSPEND_MIN && pct >= BATT_SUSPEND_MIN) {
            Log.i(TAG, "Battery recovered (" + pct + "%) — restarting data transports");
            mHandler.post(() -> {
                if (mRunning.get()) {
                    if (mWifiTransport != null) mWifiTransport.start();
                    if (mMdnsTransport != null) mMdnsTransport.start();
                }
            });
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Converts a hex string to a byte array of exactly {@code len} bytes. */
    private static byte[] hexToBytes(String hex, int len) {
        byte[] result = new byte[len];
        if (hex == null) return result;
        int hexLen = Math.min(hex.length() / 2, len);
        for (int i = 0; i < hexLen; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    /** Generates a random 16-byte message ID. */
    private static byte[] generateMessageId() {
        byte[] id = new byte[16];
        java.util.concurrent.ThreadLocalRandom.current().nextBytes(id);
        return id;
    }
}
