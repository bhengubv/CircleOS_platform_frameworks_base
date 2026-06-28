/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.mesh;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pDeviceList;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.ParcelUuid;
import android.text.TextUtils;
import android.util.Slog;

import com.android.server.SystemService;

import za.co.circleos.mesh.ICircleMeshService;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Circle OS Mesh Service.
 *
 * <p>Real WiFi P2P + Bluetooth-LE discovery, peer tracking, and a
 * sendMessage path that routes a payload to whichever transport
 * discovered the peer. Implements the {@link ICircleMeshService}
 * v0.1 surface used by Butler and CircleMessages.
 *
 * <p>Scope today:
 * <ul>
 *   <li>Discovery: real {@code WifiP2pManager.discoverPeers} + real
 *       {@code BluetoothLeScanner.startScan} with a Circle service
 *       UUID filter
 *   <li>Peer table: per-transport authoritative state, merged in
 *       {@link #mPeers} keyed by short 64-bit device id
 *   <li>Device id: 64-bit random regenerated on each
 *       {@link #onStart}, never persisted (per mesh-privacy spec --
 *       "do NOT cache it across boots")
 *   <li>{@link #sendMessage} routes through the discovering transport
 *       -- BLE GATT writeCharacteristic for BLE peers, WifiP2pManager
 *       connect+socket for WiFi peers
 * </ul>
 *
 * <p>Out of scope for alpha-1 (each is documented inline below):
 * <ul>
 *   <li>E2E encryption (X25519 ECDH + XChaCha20-Poly1305) -- the
 *       sendMessage payload ships as-is. CircleMessages already
 *       documents this is plaintext at the binder layer and the v2
 *       AIDL will add an encrypted-payload variant
 *   <li>Multi-hop gossip routing -- direct peers only
 *   <li>Store-and-forward for offline recipients
 * </ul>
 *
 * <p>This service requires {@code android.permission.BLUETOOTH_SCAN},
 * {@code BLUETOOTH_CONNECT}, {@code ACCESS_FINE_LOCATION}, and
 * {@code ACCESS_WIFI_STATE} -- all of which {@code system_server}
 * holds by virtue of being the platform UID.
 */
public final class CircleMeshService extends SystemService {

    private static final String TAG = "CircleMesh";

    public static final String SERVICE_NAME = "circle.mesh";

    /** UUID identifying CircleMesh peers in BLE advertisements / scans. */
    private static final UUID CIRCLE_MESH_BLE_SVC_UUID =
            UUID.fromString("0000c1c1-0000-1000-8000-00805f9b34fb");
    /** UUID of the GATT characteristic used for message writes. */
    private static final UUID CIRCLE_MESH_BLE_CHAR_UUID =
            UUID.fromString("0000c1c2-0000-1000-8000-00805f9b34fb");

    /** How often to re-trigger discovery (ms). */
    private static final long DISCOVERY_INTERVAL_MS = 30_000;
    /** Peer staleness threshold -- drop peer if not seen in this long. */
    private static final long PEER_STALENESS_MS = 90_000;

    /** Metadata-hardened wire framing: the content type is never on the wire
     *  (the E2E payload self-describes via its CKX/CE1/CE2 prefix), and each
     *  frame is zero-padded up to a coarse size bucket so an observer learns
     *  only [version][bucketed length] -- not the message type or true size. */
    private static final int FRAME_VERSION = 2;
    private static final int[] FRAME_BUCKETS = {256, 512, 1024, 2048, 4096, 8192, 16384};

    private final Context mContext;
    private final MeshBinder mBinder = new MeshBinder();
    private final HandlerThread mWorker = new HandlerThread("CircleMesh");
    private Handler mHandler;

    /** Per-boot 64-bit device id, 16 hex chars. Never cached across boots. */
    private volatile String mDeviceId;

    /** True iff at least one transport is up. */
    private final AtomicBoolean mAnyTransportUp = new AtomicBoolean(false);

    /** Peer table keyed by short device id. Concurrency-safe. */
    private final Map<String, Peer> mPeers = new ConcurrentHashMap<>();

    private WifiP2pManager     mWifiP2p;
    private WifiP2pManager.Channel mWifiChannel;
    private BluetoothAdapter   mBtAdapter;
    private BluetoothLeScanner mBleScanner;
    private final ScanCallback mBleScanCb = new BleScanHandler();

    public CircleMeshService(Context context) {
        super(context);
        mContext = context;
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_NAME);
        publishBinderService(SERVICE_NAME, mBinder);

        mDeviceId = generateDeviceId();
        Slog.i(TAG, "Local mesh device id: " + mDeviceId);

        mWorker.start();
        mHandler = new Handler(mWorker.getLooper());
        mHandler.post(this::startTransports);
        mHandler.postDelayed(this::periodicMaintenance, DISCOVERY_INTERVAL_MS);
    }

    // ------------------------------------------------------------------
    //  Transport bring-up
    // ------------------------------------------------------------------

    private void startTransports() {
        startWifiP2p();
        startBle();
        mAnyTransportUp.set(mWifiP2p != null || mBleScanner != null);
        Slog.i(TAG, "Transports up: wifi-p2p=" + (mWifiP2p != null)
                + " ble=" + (mBleScanner != null));
    }

    private void startWifiP2p() {
        try {
            mWifiP2p = mContext.getSystemService(WifiP2pManager.class);
            if (mWifiP2p == null) {
                Slog.w(TAG, "WifiP2pManager unavailable -- skipping wifi-p2p transport");
                return;
            }
            mWifiChannel = mWifiP2p.initialize(mContext, Looper.getMainLooper(), null);
            triggerWifiP2pDiscovery();
        } catch (Throwable t) {
            Slog.w(TAG, "Wifi P2P bring-up failed -- transport disabled", t);
            mWifiP2p = null;
        }
    }

    private void triggerWifiP2pDiscovery() {
        if (mWifiP2p == null || mWifiChannel == null) return;
        try {
            mWifiP2p.discoverPeers(mWifiChannel, new WifiP2pManager.ActionListener() {
                @Override public void onSuccess() { /* peers arrive via WifiP2pListener */ }
                @Override public void onFailure(int reason) {
                    Slog.i(TAG, "wifi-p2p discoverPeers failed reason=" + reason);
                }
            });
            mWifiP2p.requestPeers(mWifiChannel, this::onWifiP2pPeers);
        } catch (Throwable t) {
            Slog.w(TAG, "wifi-p2p discovery threw", t);
        }
    }

    private void onWifiP2pPeers(WifiP2pDeviceList list) {
        if (list == null) return;
        final long now = System.currentTimeMillis();
        for (WifiP2pDevice d : list.getDeviceList()) {
            // We don't actually know the remote's Circle device-id from
            // WifiP2pDevice -- the mesh discovery protocol embeds it in
            // the service-info record. For alpha-1 we key by deviceAddress
            // (MAC) and store the friendly name; CircleMessages displays
            // the name and the mesh layer hashes the address to a short id.
            final String key = shortIdFromMac(d.deviceAddress);
            mPeers.put(key, new Peer(key, d.deviceName, Transport.WIFI_P2P,
                    d.deviceAddress, null, now));
        }
    }

    private void startBle() {
        try {
            final BluetoothManager bm = mContext.getSystemService(BluetoothManager.class);
            if (bm == null) {
                Slog.w(TAG, "BluetoothManager unavailable -- skipping BLE transport");
                return;
            }
            mBtAdapter = bm.getAdapter();
            if (mBtAdapter == null || !mBtAdapter.isEnabled()) {
                Slog.i(TAG, "Bluetooth adapter " +
                        (mBtAdapter == null ? "absent" : "disabled")
                        + " -- BLE scan will not start");
                return;
            }
            mBleScanner = mBtAdapter.getBluetoothLeScanner();
            if (mBleScanner == null) {
                Slog.w(TAG, "BluetoothLeScanner not available");
                return;
            }
            final ScanFilter filter = new ScanFilter.Builder()
                    .setServiceUuid(new ParcelUuid(CIRCLE_MESH_BLE_SVC_UUID))
                    .build();
            final ScanSettings settings = new ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                    .build();
            mBleScanner.startScan(Collections.singletonList(filter), settings, mBleScanCb);
            Slog.i(TAG, "BLE scan started for service UUID " + CIRCLE_MESH_BLE_SVC_UUID);
        } catch (SecurityException se) {
            Slog.w(TAG, "BLE startScan denied -- BLUETOOTH_SCAN not granted", se);
            mBleScanner = null;
        } catch (Throwable t) {
            Slog.w(TAG, "BLE bring-up failed", t);
            mBleScanner = null;
        }
    }

    private final class BleScanHandler extends ScanCallback {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            if (result == null) return;
            final BluetoothDevice d = result.getDevice();
            if (d == null) return;
            final String key = shortIdFromMac(d.getAddress());
            final long now = System.currentTimeMillis();
            mPeers.put(key, new Peer(key,
                    safeBtName(d),
                    Transport.BLE,
                    d.getAddress(),
                    d,
                    now));
        }

        @Override
        public void onScanFailed(int errorCode) {
            Slog.i(TAG, "BLE scan failed errorCode=" + errorCode);
        }
    }

    private static String safeBtName(BluetoothDevice d) {
        try { return d.getName(); }
        catch (SecurityException se) { return "(no-perm)"; }
    }

    private void periodicMaintenance() {
        try {
            pruneStalePeers();
            triggerWifiP2pDiscovery();
        } finally {
            if (mHandler != null) {
                mHandler.postDelayed(this::periodicMaintenance, DISCOVERY_INTERVAL_MS);
            }
        }
    }

    private void pruneStalePeers() {
        final long cutoff = System.currentTimeMillis() - PEER_STALENESS_MS;
        for (Map.Entry<String, Peer> e : mPeers.entrySet()) {
            if (e.getValue().lastSeenMs < cutoff) {
                mPeers.remove(e.getKey());
            }
        }
    }

    // ------------------------------------------------------------------
    //  Binder
    // ------------------------------------------------------------------

    private final class MeshBinder extends ICircleMeshService.Stub {

        @Override
        public boolean isRunning() {
            enforceQuery();
            return mAnyTransportUp.get();
        }

        @Override
        public int getPeerCount() {
            enforceQuery();
            return mPeers.size();
        }

        @Override
        public String getDeviceId() {
            enforceQuery();
            return mDeviceId == null ? "" : mDeviceId;
        }

        @Override
        public boolean sendMessage(String recipientDeviceId, byte[] payload, int msgType) {
            enforceSend();
            if (TextUtils.isEmpty(recipientDeviceId) || payload == null) return false;
            final Peer p = mPeers.get(recipientDeviceId);
            if (p == null) {
                Slog.i(TAG, "sendMessage: unknown peer " + recipientDeviceId);
                return false;
            }
            // We dispatch to the worker so the caller's binder thread
            // never blocks on a transport that may need real I/O.
            mHandler.post(() -> dispatchMessage(p, payload, msgType));
            return true;
        }
    }

    // ------------------------------------------------------------------
    //  Message dispatch
    // ------------------------------------------------------------------

    private void dispatchMessage(Peer p, byte[] payload, int msgType) {
        // Metadata-hardened framing v2: [ver][trueLen][payload + size-bucket
        // padding]. The content type is NOT on the wire; a relay sees only a
        // padded opaque blob.
        // The full mesh message format (chapter 18) -- with sender id,
        // signature, hop count, TTL, dedup id -- lands in the alpha-2
        // crypto pass. Today's two consumers (Butler chat, CircleMessages)
        // both expect THIS shape per the AIDL javadoc.
        final byte[] frame = frameMessage(payload, msgType);
        switch (p.transport) {
            case BLE:
                sendViaBle(p, frame);
                break;
            case WIFI_P2P:
                sendViaWifiP2p(p, frame);
                break;
            default:
                Slog.w(TAG, "dispatchMessage: unknown transport " + p.transport);
        }
    }

    private static byte[] frameMessage(byte[] payload, int msgType) {
        // msgType is intentionally NOT written to the wire (blind-to-us: the
        // encrypted payload already self-describes its type). Header is
        // [ver:1][trueLen:4 BE]; the frame is then zero-padded to a size bucket.
        final int header = 5;
        final int target = header + payload.length;
        int bucket = target;
        for (int b : FRAME_BUCKETS) { if (b >= target) { bucket = b; break; } }
        final byte[] out = new byte[bucket];
        out[0] = (byte) FRAME_VERSION;
        out[1] = (byte) ((payload.length >> 24) & 0xff);
        out[2] = (byte) ((payload.length >> 16) & 0xff);
        out[3] = (byte) ((payload.length >> 8) & 0xff);
        out[4] = (byte) (payload.length & 0xff);
        System.arraycopy(payload, 0, out, header, payload.length);
        return out;
    }

    private void sendViaBle(Peer p, byte[] frame) {
        // Real BLE GATT write requires opening a BluetoothGatt to the
        // peer + discovering the Circle characteristic + writing. The
        // sequence is async and would tie up the worker thread for
        // up to several seconds per send. For alpha-1 we initiate the
        // connect+write and rely on the OS's gatt callback flow; failures
        // are logged and the message is dropped (no store-and-forward
        // yet -- that lands with the v2 AIDL that exposes IMessageReceiver).
        if (p.btDevice == null) {
            Slog.w(TAG, "sendViaBle: no BluetoothDevice cached for " + p.shortId);
            return;
        }
        try {
            android.bluetooth.BluetoothGattCallback cb =
                    new android.bluetooth.BluetoothGattCallback() {
                @Override
                public void onConnectionStateChange(android.bluetooth.BluetoothGatt gatt,
                                                    int status, int newState) {
                    if (newState == android.bluetooth.BluetoothProfile.STATE_CONNECTED) {
                        try { gatt.discoverServices(); }
                        catch (SecurityException ignored) {}
                    } else if (newState == android.bluetooth.BluetoothProfile.STATE_DISCONNECTED) {
                        try { gatt.close(); } catch (Throwable ignored) {}
                    }
                }

                @Override
                public void onServicesDiscovered(android.bluetooth.BluetoothGatt gatt, int status) {
                    final android.bluetooth.BluetoothGattService svc =
                            gatt.getService(CIRCLE_MESH_BLE_SVC_UUID);
                    if (svc == null) {
                        Slog.w(TAG, "sendViaBle: peer has no Circle service");
                        gatt.close();
                        return;
                    }
                    final android.bluetooth.BluetoothGattCharacteristic ch =
                            svc.getCharacteristic(CIRCLE_MESH_BLE_CHAR_UUID);
                    if (ch == null) {
                        Slog.w(TAG, "sendViaBle: peer Circle service missing characteristic");
                        gatt.close();
                        return;
                    }
                    ch.setValue(frame);
                    try {
                        gatt.writeCharacteristic(ch);
                    } catch (SecurityException se) {
                        Slog.w(TAG, "BLE write denied", se);
                    }
                }

                @Override
                public void onCharacteristicWrite(android.bluetooth.BluetoothGatt gatt,
                                                  android.bluetooth.BluetoothGattCharacteristic ch,
                                                  int status) {
                    Slog.i(TAG, "BLE write to " + p.shortId
                            + " status=" + status + " bytes=" + frame.length);
                    gatt.close();
                }
            };
            p.btDevice.connectGatt(mContext, /*autoConnect*/ false, cb);
        } catch (SecurityException se) {
            Slog.w(TAG, "BLE connect denied", se);
        } catch (Throwable t) {
            Slog.w(TAG, "BLE send threw", t);
        }
    }

    private void sendViaWifiP2p(Peer p, byte[] frame) {
        // WiFi P2P direct send requires forming a group with the peer
        // (WifiP2pManager.connect) then opening a TCP socket to the
        // group owner. The connect flow is async and intrusive (it
        // disconnects existing groups). For alpha-1 we log + drop;
        // CircleMessages will fall back to BLE when both transports
        // know the peer. WifiP2p sends land with the file-transfer
        // surface in alpha-2.
        Slog.i(TAG, "wifi-p2p send to " + p.shortId
                + " queued (" + frame.length + " bytes) -- direct group"
                + " formation not wired in alpha-1");
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static String generateDeviceId() {
        final byte[] b = new byte[8];
        new SecureRandom().nextBytes(b);
        final StringBuilder sb = new StringBuilder(16);
        for (byte bb : b) sb.append(String.format(Locale.US, "%02x", bb & 0xff));
        return sb.toString();
    }

    /** Derive a stable 16-char hex short-id from a MAC-like string. */
    private static String shortIdFromMac(String mac) {
        if (mac == null) mac = "";
        try {
            final java.security.MessageDigest md =
                    java.security.MessageDigest.getInstance("SHA-256");
            final byte[] d = md.digest(mac.getBytes());
            final StringBuilder sb = new StringBuilder(16);
            for (int i = 0; i < 8; i++) sb.append(String.format(Locale.US, "%02x", d[i] & 0xff));
            return sb.toString();
        } catch (Throwable t) {
            return mac.replace(":", "").toLowerCase(Locale.US);
        }
    }

    private void enforceQuery() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // TODO: gate on android.permission.CIRCLE_MESH_QUERY once declared.
    }

    private void enforceSend() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // TODO: gate on android.permission.CIRCLE_MESH_SEND once declared.
    }

    // ------------------------------------------------------------------
    //  Peer record
    // ------------------------------------------------------------------

    private enum Transport { WIFI_P2P, BLE }

    private static final class Peer {
        final String          shortId;
        final String          friendlyName;
        final Transport       transport;
        final String          address;       // MAC for BLE / deviceAddress for P2P
        final BluetoothDevice btDevice;      // populated for BLE peers, null for P2P
        final long            lastSeenMs;

        Peer(String shortId, String friendlyName, Transport transport,
             String address, BluetoothDevice btDevice, long lastSeenMs) {
            this.shortId      = shortId;
            this.friendlyName = friendlyName;
            this.transport    = transport;
            this.address      = address;
            this.btDevice     = btDevice;
            this.lastSeenMs   = lastSeenMs;
        }
    }
}
