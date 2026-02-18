/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pDeviceList;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.ParcelUuid;
import android.util.Slog;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Discovers nearby CircleOS devices that hold OTA update chunks.
 *
 * Three discovery methods run concurrently:
 *   1. mDNS (NsdManager) — same-LAN WiFi: browses _circleos-mesh._tcp
 *   2. WiFi Direct (WifiP2pManager) — peer-to-peer; sends UDP broadcast ANNOUNCE
 *   3. Bluetooth LE — scans for service UUID CMSH; WiFi address exchanged via BLE
 *
 * Peers are de-duplicated by IP address. All callbacks arrive on the background
 * HandlerThread and are forwarded to the supplied {@link PeerListener}.
 */
public final class PeerDiscovery {

    private static final String TAG = "PeerDiscovery";

    /** mDNS service type for the CircleOS mesh service. */
    private static final String NSD_SERVICE_TYPE = "_circleos-mesh._tcp";
    /** mDNS service name prefix when registering our own service. */
    private static final String NSD_SERVICE_NAME = "circleos-mesh";

    /** TCP/UDP port used for chunk serving and peer discovery. */
    static final int MESH_PORT = 9847;

    /**
     * BLE service UUID advertising a CircleOS mesh node.
     * "0000CMSH-0000-1000-8000-00805F9B34FB" (placeholder)
     */
    private static final UUID BLE_SERVICE_UUID =
            UUID.fromString("0000CMSH-0000-1000-8000-00805F9B34FB");

    /**
     * GATT characteristic UUID that carries the peer's WiFi IP:port string.
     * Matches the UUID registered by BluetoothLeTransport on the server side.
     * Value format: "192.168.1.42:9847" (UTF-8, no null terminator).
     */
    private static final UUID WIFI_IP_CHAR_UUID =
            UUID.fromString("00001824-0000-1000-8000-00805f9b34fb");

    // -------------------------------------------------------------------------
    // Inner types
    // -------------------------------------------------------------------------

    /** Transport method by which a peer was discovered. */
    public enum DiscoveryMethod {
        WIFI_DIRECT,
        MDNS,
        BLUETOOTH_LE
    }

    /**
     * Information about a discovered peer node.
     */
    public static final class PeerInfo {
        /** Stable identifier (IP address string). */
        public final String id;
        /** Reachable IP address or hostname. */
        public final String address;
        /** TCP port for chunk transfers (normally {@link #MESH_PORT}). */
        public final int port;
        /** OTA version this peer holds chunks for. */
        public final String version;
        /** Chunk availability bitmap received from the peer. */
        public final byte[] chunkBitmap;
        /** Transport used to find this peer. */
        public final DiscoveryMethod method;

        PeerInfo(String id, String address, int port, String version,
                byte[] chunkBitmap, DiscoveryMethod method) {
            this.id          = id;
            this.address     = address;
            this.port        = port;
            this.version     = version;
            this.chunkBitmap = chunkBitmap;
            this.method      = method;
        }

        @Override
        public String toString() {
            return "PeerInfo{id=" + id + " addr=" + address + ":" + port
                    + " method=" + method + "}";
        }
    }

    /**
     * Callbacks delivered when peers are found or lost.
     */
    public interface PeerListener {
        /** Called when a new peer is discovered or its bitmap is updated. */
        void onPeerFound(PeerInfo peer);
        /** Called when a peer is no longer reachable. */
        void onPeerLost(String peerId);
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private final Context        mContext;
    private final PeerListener   mListener;
    private final HandlerThread  mThread;
    private final Handler        mHandler;
    private final ExecutorService mConnectPool;

    /** Known peers, keyed by IP address string. */
    private final Map<String, PeerInfo> mPeers = new HashMap<>();

    private String mTargetVersion;
    private volatile boolean mRunning = false;

    // NSD (mDNS)
    private NsdManager              mNsdManager;
    private NsdManager.DiscoveryListener  mNsdDiscoveryListener;
    private NsdManager.RegistrationListener mNsdRegistrationListener;

    // WiFi Direct
    private WifiP2pManager          mWifiP2pManager;
    private WifiP2pManager.Channel  mWifiP2pChannel;

    // Bluetooth LE
    private BluetoothLeScanner      mBleScanner;
    private ScanCallback            mBleScanCallback;

    /** BLE addresses for which a GATT connection is currently in progress. */
    private final Set<String> mGattConnecting =
            Collections.synchronizedSet(new HashSet<>());

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * @param ctx      System context.
     * @param listener Callback interface for peer events.
     */
    public PeerDiscovery(Context ctx, PeerListener listener) {
        mContext     = ctx;
        mListener    = listener;
        mConnectPool = Executors.newFixedThreadPool(4);

        mThread = new HandlerThread("PeerDiscovery");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Starts all three discovery methods for the given OTA version.
     *
     * @param version OTA version string to search for.
     */
    public void startDiscovery(String version) {
        mTargetVersion = version;
        mRunning = true;
        Slog.i(TAG, "startDiscovery: version=" + version);

        mHandler.post(() -> {
            startMdnsDiscovery(version);
            startWifiDirectDiscovery(version);
            startBleDiscovery();
        });
    }

    /**
     * Stops all running discovery methods and clears the peer list.
     */
    public void stopDiscovery() {
        mRunning = false;
        Slog.i(TAG, "stopDiscovery");

        mHandler.post(() -> {
            stopMdnsDiscovery();
            stopWifiDirectDiscovery();
            stopBleDiscovery();
            synchronized (mPeers) {
                mPeers.clear();
            }
        });
    }

    /**
     * Registers this device as a CircleOS mesh node via mDNS so that other
     * devices on the same LAN can discover it.
     *
     * @param version     The OTA version we hold chunks for.
     * @param chunkBitmap Our current chunk availability bitmap.
     */
    public void registerSelf(String version, byte[] chunkBitmap) {
        mHandler.post(() -> {
            NsdManager nsd = (NsdManager) mContext.getSystemService(Context.NSD_SERVICE);
            if (nsd == null) {
                Slog.w(TAG, "registerSelf: NsdManager unavailable");
                return;
            }

            NsdServiceInfo info = new NsdServiceInfo();
            info.setServiceName(NSD_SERVICE_NAME + "-" + sanitizeVersion(version));
            info.setServiceType(NSD_SERVICE_TYPE);
            info.setPort(MESH_PORT);

            mNsdRegistrationListener = new NsdManager.RegistrationListener() {
                @Override public void onRegistrationFailed(NsdServiceInfo si, int code) {
                    Slog.w(TAG, "mDNS registration failed: " + code);
                }
                @Override public void onUnregistrationFailed(NsdServiceInfo si, int code) {
                    Slog.w(TAG, "mDNS unregistration failed: " + code);
                }
                @Override public void onServiceRegistered(NsdServiceInfo si) {
                    Slog.i(TAG, "mDNS registered: " + si.getServiceName());
                }
                @Override public void onServiceUnregistered(NsdServiceInfo si) {
                    Slog.i(TAG, "mDNS unregistered: " + si.getServiceName());
                }
            };

            nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, mNsdRegistrationListener);
        });
    }

    // -------------------------------------------------------------------------
    // mDNS discovery
    // -------------------------------------------------------------------------

    private void startMdnsDiscovery(String version) {
        mNsdManager = (NsdManager) mContext.getSystemService(Context.NSD_SERVICE);
        if (mNsdManager == null) {
            Slog.w(TAG, "NsdManager unavailable — skipping mDNS discovery");
            return;
        }

        mNsdDiscoveryListener = new NsdManager.DiscoveryListener() {
            @Override public void onStartDiscoveryFailed(String type, int code) {
                Slog.w(TAG, "mDNS discovery start failed: " + code);
            }
            @Override public void onStopDiscoveryFailed(String type, int code) {
                Slog.w(TAG, "mDNS discovery stop failed: " + code);
            }
            @Override public void onDiscoveryStarted(String type) {
                Slog.i(TAG, "mDNS discovery started for " + type);
            }
            @Override public void onDiscoveryStopped(String type) {
                Slog.i(TAG, "mDNS discovery stopped for " + type);
            }

            @Override
            public void onServiceFound(NsdServiceInfo serviceInfo) {
                if (!mRunning) return;
                Slog.d(TAG, "mDNS service found: " + serviceInfo.getServiceName());
                // Resolve to get IP + port
                mNsdManager.resolveService(serviceInfo, new NsdManager.ResolveListener() {
                    @Override public void onResolveFailed(NsdServiceInfo si, int code) {
                        Slog.w(TAG, "mDNS resolve failed: " + code + " for " + si.getServiceName());
                    }
                    @Override public void onServiceResolved(NsdServiceInfo si) {
                        if (!mRunning) return;
                        InetAddress host = si.getHost();
                        int port = si.getPort();
                        if (host == null) return;
                        String address = host.getHostAddress();
                        // Connect and probe for chunk bitmap
                        mConnectPool.execute(() -> probeAndRegisterPeer(
                                address, port, DiscoveryMethod.MDNS));
                    }
                });
            }

            @Override
            public void onServiceLost(NsdServiceInfo serviceInfo) {
                Slog.d(TAG, "mDNS service lost: " + serviceInfo.getServiceName());
                // Best-effort: we cannot cheaply map a service name back to an IP here.
                // The peer will be removed if subsequent chunk requests fail.
            }
        };

        mNsdManager.discoverServices(
                NSD_SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, mNsdDiscoveryListener);
    }

    private void stopMdnsDiscovery() {
        if (mNsdManager != null && mNsdDiscoveryListener != null) {
            try {
                mNsdManager.stopServiceDiscovery(mNsdDiscoveryListener);
            } catch (Exception e) {
                Slog.w(TAG, "stopMdnsDiscovery error", e);
            }
            mNsdDiscoveryListener = null;
        }
        if (mNsdManager != null && mNsdRegistrationListener != null) {
            try {
                mNsdManager.unregisterService(mNsdRegistrationListener);
            } catch (Exception e) {
                Slog.w(TAG, "mDNS unregister error", e);
            }
            mNsdRegistrationListener = null;
        }
    }

    // -------------------------------------------------------------------------
    // WiFi Direct discovery
    // -------------------------------------------------------------------------

    private void startWifiDirectDiscovery(String version) {
        mWifiP2pManager = (WifiP2pManager) mContext.getSystemService(Context.WIFI_P2P_SERVICE);
        if (mWifiP2pManager == null) {
            Slog.w(TAG, "WifiP2pManager unavailable — skipping WiFi Direct discovery");
            return;
        }

        mWifiP2pChannel = mWifiP2pManager.initialize(
                mContext, mThread.getLooper(), null);

        mWifiP2pManager.discoverPeers(mWifiP2pChannel, new WifiP2pManager.ActionListener() {
            @Override public void onSuccess() {
                Slog.i(TAG, "WiFi Direct discovery initiated");
                // Request peer list after a short delay to let scan complete
                mHandler.postDelayed(() -> requestWifiDirectPeerList(version), 3000L);
            }
            @Override public void onFailure(int reason) {
                Slog.w(TAG, "WiFi Direct discoverPeers failed: reason=" + reason);
            }
        });
    }

    private void requestWifiDirectPeerList(String version) {
        if (!mRunning || mWifiP2pManager == null || mWifiP2pChannel == null) return;

        mWifiP2pManager.requestPeers(mWifiP2pChannel,
                (WifiP2pDeviceList deviceList) -> {
                    if (deviceList == null) return;
                    for (WifiP2pDevice device : deviceList.getDeviceList()) {
                        // WiFi Direct device address is a MAC, not IP.
                        // After a p2p connection the group owner IP is typically 192.168.49.1.
                        // Here we broadcast an ANNOUNCE on 9847 and listen for replies.
                        // Real IP is obtained after connection; for now we record MAC as id
                        // and probe via UDP broadcast on the P2P subnet.
                        Slog.d(TAG, "WiFi Direct peer: " + device.deviceName
                                + " addr=" + device.deviceAddress);
                        sendUdpAnnounce(version);
                    }
                });

        // Re-scan periodically while running
        if (mRunning) {
            mHandler.postDelayed(() -> requestWifiDirectPeerList(version), 30_000L);
        }
    }

    /**
     * Sends a UDP broadcast ANNOUNCE on the WiFi Direct subnet (192.168.49.255)
     * so that connected group members know we are looking for chunks.
     */
    private void sendUdpAnnounce(String version) {
        mConnectPool.execute(() -> {
            byte[] announce = MeshProtocol.buildAnnounce(version, new byte[0]);
            try (DatagramSocket sock = new DatagramSocket()) {
                sock.setBroadcast(true);
                InetAddress bcast = InetAddress.getByName("192.168.49.255");
                DatagramPacket pkt = new DatagramPacket(announce, announce.length, bcast, MESH_PORT);
                sock.send(pkt);
                Slog.d(TAG, "UDP announce sent on WiFi Direct subnet");
            } catch (IOException e) {
                Slog.d(TAG, "UDP announce failed (no WiFi Direct link?): " + e.getMessage());
            }
        });
    }

    private void stopWifiDirectDiscovery() {
        if (mWifiP2pManager != null && mWifiP2pChannel != null) {
            mWifiP2pManager.stopPeerDiscovery(mWifiP2pChannel, new WifiP2pManager.ActionListener() {
                @Override public void onSuccess() {}
                @Override public void onFailure(int reason) {}
            });
        }
    }

    // -------------------------------------------------------------------------
    // Bluetooth LE discovery
    // -------------------------------------------------------------------------

    private void startBleDiscovery() {
        BluetoothManager btMgr =
                (BluetoothManager) mContext.getSystemService(Context.BLUETOOTH_SERVICE);
        if (btMgr == null) {
            Slog.w(TAG, "BluetoothManager unavailable — skipping BLE discovery");
            return;
        }
        BluetoothAdapter adapter = btMgr.getAdapter();
        if (adapter == null || !adapter.isEnabled()) {
            Slog.w(TAG, "Bluetooth disabled — skipping BLE discovery");
            return;
        }

        mBleScanner = adapter.getBluetoothLeScanner();
        if (mBleScanner == null) {
            Slog.w(TAG, "BluetoothLeScanner unavailable");
            return;
        }

        ScanFilter filter = new ScanFilter.Builder()
                .setServiceUuid(new ParcelUuid(BLE_SERVICE_UUID))
                .build();

        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                .build();

        mBleScanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                if (!mRunning) return;
                handleBleScanResult(result);
            }

            @Override
            public void onBatchScanResults(List<ScanResult> results) {
                if (!mRunning) return;
                for (ScanResult r : results) handleBleScanResult(r);
            }

            @Override
            public void onScanFailed(int errorCode) {
                Slog.w(TAG, "BLE scan failed: errorCode=" + errorCode);
            }
        };

        mBleScanner.startScan(
                Collections.singletonList(filter), settings, mBleScanCallback);
        Slog.i(TAG, "BLE scan started for service UUID " + BLE_SERVICE_UUID);
    }

    private void handleBleScanResult(ScanResult result) {
        BluetoothDevice device = result.getDevice();
        final String bleAddr = device.getAddress();
        Slog.d(TAG, "BLE peer found: " + bleAddr + " rssi=" + result.getRssi());

        // Skip if we already have a live peer entry keyed by this BLE address.
        synchronized (mPeers) {
            if (mPeers.containsKey(bleAddr)) return;
        }
        // Skip if a GATT connection attempt is already in flight for this address.
        if (!mGattConnecting.add(bleAddr)) return;

        device.connectGatt(mContext, /* autoConnect= */ false, new BluetoothGattCallback() {

            @Override
            public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    Slog.d(TAG, "GATT connected to " + bleAddr + "; discovering services");
                    gatt.discoverServices();
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    Slog.d(TAG, "GATT disconnected from " + bleAddr);
                    mGattConnecting.remove(bleAddr);
                    gatt.close();
                }
            }

            @Override
            public void onServicesDiscovered(BluetoothGatt gatt, int status) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    Slog.w(TAG, "GATT service discovery failed on " + bleAddr + ": " + status);
                    mGattConnecting.remove(bleAddr);
                    gatt.disconnect();
                    return;
                }
                BluetoothGattService service = gatt.getService(BLE_SERVICE_UUID);
                if (service == null) {
                    Slog.w(TAG, "GATT: CircleOS mesh service not found on " + bleAddr);
                    mGattConnecting.remove(bleAddr);
                    gatt.disconnect();
                    return;
                }
                BluetoothGattCharacteristic wifiIpChar = service.getCharacteristic(WIFI_IP_CHAR_UUID);
                if (wifiIpChar == null) {
                    Slog.w(TAG, "GATT: WiFi-IP characteristic not found on " + bleAddr);
                    mGattConnecting.remove(bleAddr);
                    gatt.disconnect();
                    return;
                }
                if (!gatt.readCharacteristic(wifiIpChar)) {
                    Slog.w(TAG, "GATT: readCharacteristic initiation failed on " + bleAddr);
                    mGattConnecting.remove(bleAddr);
                    gatt.disconnect();
                }
            }

            // API 33+ override — preferred on Android 14.
            @Override
            public void onCharacteristicRead(BluetoothGatt gatt,
                    BluetoothGattCharacteristic characteristic,
                    byte[] value, int status) {
                mGattConnecting.remove(bleAddr);
                gatt.disconnect();

                if (status != BluetoothGatt.GATT_SUCCESS || value == null || value.length == 0) {
                    Slog.w(TAG, "GATT: characteristic read failed on " + bleAddr + ": " + status);
                    return;
                }
                // Value format: "192.168.1.42:9847" (UTF-8)
                String raw = new String(value, StandardCharsets.UTF_8).trim();
                int sep = raw.lastIndexOf(':');
                if (sep < 7) { // minimal valid: "1.2.3.4:1"
                    Slog.w(TAG, "GATT: unexpected WiFi-IP value from " + bleAddr + ": \"" + raw + "\"");
                    return;
                }
                String wifiIp = raw.substring(0, sep);
                int wifiPort;
                try {
                    wifiPort = Integer.parseInt(raw.substring(sep + 1));
                } catch (NumberFormatException e) {
                    wifiPort = MESH_PORT;
                }
                Slog.i(TAG, "GATT: BLE peer " + bleAddr + " → WiFi " + wifiIp + ":" + wifiPort);
                final String ip   = wifiIp;
                final int    port = wifiPort;
                mConnectPool.execute(() -> probeAndRegisterPeer(ip, port, DiscoveryMethod.BLUETOOTH_LE));
            }
        }, BluetoothDevice.TRANSPORT_LE);
    }

    private void stopBleDiscovery() {
        if (mBleScanner != null && mBleScanCallback != null) {
            try {
                mBleScanner.stopScan(mBleScanCallback);
            } catch (Exception e) {
                Slog.w(TAG, "stopBleDiscovery error", e);
            }
            mBleScanCallback = null;
        }
    }

    // -------------------------------------------------------------------------
    // Peer probing (shared by mDNS and WiFi Direct)
    // -------------------------------------------------------------------------

    /**
     * Opens a TCP connection to the given address/port, sends a DISCOVER
     * message, reads back the CHUNK_MAP, and registers the peer if it holds
     * chunks for our target version.
     */
    private void probeAndRegisterPeer(String address, int port, DiscoveryMethod method) {
        String targetVersion = mTargetVersion;
        if (targetVersion == null || !mRunning) return;

        byte[] bitmap = ChunkClient.staticRequestChunkMap(address, port, targetVersion);
        if (bitmap == null) {
            Slog.d(TAG, "probeAndRegisterPeer: no bitmap from " + address);
            return;
        }

        // Check that the peer actually has something
        boolean hasAny = false;
        for (byte b : bitmap) {
            if (b != 0) { hasAny = true; break; }
        }
        if (!hasAny) {
            Slog.d(TAG, "probeAndRegisterPeer: peer " + address + " has no chunks");
            return;
        }

        PeerInfo peer = new PeerInfo(address, address, port, targetVersion, bitmap, method);
        boolean isNew;
        synchronized (mPeers) {
            isNew = !mPeers.containsKey(address);
            mPeers.put(address, peer);
        }

        Slog.i(TAG, (isNew ? "New" : "Updated") + " peer: " + peer);
        mListener.onPeerFound(peer);
    }

    /**
     * Marks a peer as lost by IP address, removes it from the map, and fires
     * the listener callback.
     */
    private void removePeer(String address) {
        synchronized (mPeers) {
            if (mPeers.remove(address) == null) return;
        }
        Slog.i(TAG, "Peer lost: " + address);
        mListener.onPeerLost(address);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String sanitizeVersion(String version) {
        if (version == null) return "unknown";
        return version.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
