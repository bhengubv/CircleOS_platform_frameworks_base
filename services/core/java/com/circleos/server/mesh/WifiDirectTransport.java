/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.content.Context;
import android.net.wifi.p2p.WifiP2pManager;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceInfo;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceRequest;
import android.util.Log;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * WiFi Direct transport for Circle Mesh.
 *
 * <p>Advertises this device using a Bonjour-over-WiFi-P2P DNS-SD service record
 * ({@code _circlemesh._tcp}) and listens on TCP port {@value #MESH_PORT} for
 * inbound connections.
 *
 * <p>Wire framing: 4-byte big-endian length prefix followed by the raw frame bytes.
 *
 * <p>Peer discovery triggers {@link PeerDiscoveryListener#onPeerDiscovered} with
 * the discovered peer's IP address extracted from the TXT record.
 */
public class WifiDirectTransport extends MeshTransport {

    private static final String TAG = "MeshWifiDirect";

    /** TCP port for Circle Mesh data exchange over WiFi Direct. */
    static final int MESH_PORT = 9847;

    private static final String SERVICE_TYPE  = "_circlemesh._tcp";
    private static final String SERVICE_NAME  = "CircleMesh";

    private final Context        mContext;
    private final String         mDeviceId;
    private final String         mCapabilities;
    private final String         mVersion;

    private WifiP2pManager       mWifiP2pManager;
    private WifiP2pManager.Channel mWifiP2pChannel;

    private ServerSocket         mServerSocket;
    private final ExecutorService mExecutor = Executors.newCachedThreadPool();
    private final AtomicBoolean  mRunning   = new AtomicBoolean(false);

    /** Local IP address included in DNS-SD TXT record so peers can TCP-connect to us. */
    private volatile String      mLocalIp;

    // ── Constructor ───────────────────────────────────────────────────────────

    /**
     * @param context      Application context.
     * @param deviceId     Local 8-char hex device ID to advertise.
     * @param capabilities Comma-separated capability set (e.g. "OTA,MSG,FILE").
     * @param version      CircleOS version string (e.g. "0.1.0-alpha").
     */
    public WifiDirectTransport(Context context, String deviceId,
            String capabilities, String version) {
        mContext      = context;
        mDeviceId     = deviceId;
        mCapabilities = capabilities;
        mVersion      = version;
    }

    // ── MeshTransport ─────────────────────────────────────────────────────────

    @Override
    public String getType() { return TYPE_WIFI_DIRECT; }

    @Override
    public boolean isActive() { return mRunning.get(); }

    @Override
    public void start() {
        if (!mRunning.compareAndSet(false, true)) return;
        Log.i(TAG, "Starting WiFi Direct transport");

        // Initialise WifiP2p
        mWifiP2pManager = (WifiP2pManager) mContext.getSystemService(Context.WIFI_P2P_SERVICE);
        if (mWifiP2pManager == null) {
            Log.e(TAG, "WifiP2pManager not available");
            mRunning.set(false);
            return;
        }
        mWifiP2pChannel = mWifiP2pManager.initialize(mContext,
                mContext.getMainLooper(), null);

        // Start TCP server
        mExecutor.submit(this::runServer);

        // Register service advertisement
        registerService();

        // Discover peers
        discoverServices();
    }

    @Override
    public void stop() {
        if (!mRunning.compareAndSet(true, false)) return;
        Log.i(TAG, "Stopping WiFi Direct transport");

        if (mWifiP2pManager != null && mWifiP2pChannel != null) {
            mWifiP2pManager.clearLocalServices(mWifiP2pChannel, null);
            mWifiP2pManager.clearServiceRequests(mWifiP2pChannel, null);
        }

        try {
            if (mServerSocket != null) mServerSocket.close();
        } catch (IOException e) {
            Log.w(TAG, "Error closing server socket", e);
        }
    }

    @Override
    public boolean send(String address, byte[] frame) {
        // address format: "ip:port" e.g. "192.168.49.1:9847"
        String[] parts = address.split(":");
        if (parts.length < 2) {
            Log.w(TAG, "send: invalid address format: " + address);
            return false;
        }
        String host = parts[0];
        int port;
        try {
            port = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            port = MESH_PORT;
        }

        final String finalHost = host;
        final int finalPort    = port;
        mExecutor.submit(() -> {
            try (Socket sock = new Socket()) {
                sock.connect(new InetSocketAddress(finalHost, finalPort), 5_000);
                DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
                dos.writeInt(frame.length);
                dos.write(frame);
                dos.flush();
                Log.d(TAG, "Sent " + frame.length + " bytes to " + finalHost + ":" + finalPort);
            } catch (IOException e) {
                Log.w(TAG, "send() failed to " + finalHost + ":" + finalPort + ": " + e.getMessage());
                if (mDiscoveryListener != null) mDiscoveryListener.onPeerLost(address);
            }
        });
        return true;
    }

    /**
     * Sets the local IP address advertised in the DNS-SD TXT record.
     *
     * <p>Must be called after the TCP server has bound and the local WiFi
     * interface address is known (typically 192.168.49.x for a WiFi Direct
     * group owner, or DHCP-assigned for clients).  Re-registers the service
     * record immediately so newly discovered peers get the updated IP.
     *
     * @param localIp IPv4 address string (e.g. "192.168.49.1").
     */
    public void setLocalIp(String localIp) {
        mLocalIp = localIp;
        Log.d(TAG, "Local IP updated: " + localIp + " — re-registering DNS-SD service");
        if (mRunning.get()) {
            registerService();
        }
    }

    @Override
    public void announce(byte[] frame) {
        // Broadcast to all currently known peers — handled at MeshRouter level
        // WiFi Direct specific: update the TXT record to signal presence
        Log.d(TAG, "announce() — service record will be refreshed");
        registerService(); // re-advertise with up-to-date info
    }

    // ── Server ────────────────────────────────────────────────────────────────

    private void runServer() {
        try {
            mServerSocket = new ServerSocket(MESH_PORT);
            Log.i(TAG, "TCP server listening on port " + MESH_PORT);
            while (mRunning.get()) {
                Socket client = mServerSocket.accept();
                mExecutor.submit(() -> handleInbound(client));
            }
        } catch (IOException e) {
            if (mRunning.get()) {
                Log.e(TAG, "Server socket error", e);
            }
        }
    }

    private void handleInbound(Socket socket) {
        String from = socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
        Log.d(TAG, "Inbound connection from " + from);
        try (DataInputStream dis = new DataInputStream(socket.getInputStream())) {
            while (mRunning.get()) {
                int len = dis.readInt();
                if (len <= 0 || len > 4 * 1024 * 1024) {
                    Log.w(TAG, "Invalid frame length " + len + " from " + from);
                    break;
                }
                byte[] frame = new byte[len];
                dis.readFully(frame);
                if (mMessageListener != null) {
                    mMessageListener.onMessageReceived(from, TYPE_WIFI_DIRECT, frame);
                }
            }
        } catch (IOException e) {
            Log.d(TAG, "Connection closed from " + from + ": " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    // ── Service advertisement ─────────────────────────────────────────────────

    private void registerService() {
        if (mWifiP2pManager == null || mWifiP2pChannel == null) return;

        Map<String, String> record = new HashMap<>();
        record.put("v",   "1");
        record.put("id",  mDeviceId);
        record.put("caps", mCapabilities != null ? mCapabilities : "");
        record.put("ver", mVersion != null ? mVersion : "");
        record.put("port", String.valueOf(MESH_PORT));
        // Include local IP so discovering peers can open a TCP connection directly.
        // Without this, the MAC address from WifiP2pDevice cannot be used for TCP.
        if (mLocalIp != null) record.put("ip", mLocalIp);

        WifiP2pDnsSdServiceInfo info = WifiP2pDnsSdServiceInfo.newInstance(
                SERVICE_NAME, SERVICE_TYPE, record);

        mWifiP2pManager.clearLocalServices(mWifiP2pChannel, new WifiP2pManager.ActionListener() {
            @Override public void onSuccess() {
                mWifiP2pManager.addLocalService(mWifiP2pChannel, info,
                        new WifiP2pManager.ActionListener() {
                            @Override public void onSuccess() {
                                Log.d(TAG, "Service registered: " + SERVICE_NAME);
                            }
                            @Override public void onFailure(int reason) {
                                Log.w(TAG, "addLocalService failed: " + reason);
                            }
                        });
            }
            @Override public void onFailure(int reason) {
                Log.w(TAG, "clearLocalServices failed: " + reason);
            }
        });
    }

    // ── Peer discovery ────────────────────────────────────────────────────────

    private void discoverServices() {
        if (mWifiP2pManager == null || mWifiP2pChannel == null) return;

        // TXT record callback
        WifiP2pManager.DnsSdTxtRecordListener txtListener = (fullDomain, record, device) -> {
            String peerId   = record.get("id");
            String peerCaps = record.get("caps");
            String portStr  = record.get("port");
            String peerIp   = record.get("ip");  // IP address advertised by the peer
            int port = MESH_PORT;
            try { if (portStr != null) port = Integer.parseInt(portStr); } catch (NumberFormatException ignored) {}

            // Prefer the explicit "ip" field from the TXT record.
            // Falling back to device.deviceAddress would give a MAC address,
            // which is useless for TCP connections.
            if (peerIp == null || peerIp.isEmpty()) {
                Log.d(TAG, "TXT record from " + device.deviceName
                        + " has no 'ip' field — skipping until peer sets local IP");
                return;
            }
            Log.d(TAG, "TXT record from " + device.deviceName
                    + " id=" + peerId + " ip=" + peerIp + " caps=" + peerCaps);

            if (peerId != null && mDiscoveryListener != null) {
                mDiscoveryListener.onPeerDiscovered(peerId, peerIp, port, TYPE_WIFI_DIRECT, peerCaps);
            }
        };

        // Service response callback
        WifiP2pManager.DnsSdServiceResponseListener serviceListener = (instanceName, registrationType, device) -> {
            Log.d(TAG, "Service found: " + instanceName + " from " + device.deviceName);
        };

        mWifiP2pManager.setDnsSdResponseListeners(mWifiP2pChannel, serviceListener, txtListener);

        WifiP2pDnsSdServiceRequest request = WifiP2pDnsSdServiceRequest.newInstance(SERVICE_TYPE);
        mWifiP2pManager.addServiceRequest(mWifiP2pChannel, request,
                new WifiP2pManager.ActionListener() {
                    @Override public void onSuccess() {
                        mWifiP2pManager.discoverServices(mWifiP2pChannel,
                                new WifiP2pManager.ActionListener() {
                                    @Override public void onSuccess() {
                                        Log.i(TAG, "WiFi P2P service discovery started");
                                    }
                                    @Override public void onFailure(int reason) {
                                        Log.w(TAG, "discoverServices failed: " + reason);
                                    }
                                });
                    }
                    @Override public void onFailure(int reason) {
                        Log.w(TAG, "addServiceRequest failed: " + reason);
                    }
                });
    }
}
