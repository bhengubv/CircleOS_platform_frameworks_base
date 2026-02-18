/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.util.Log;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * mDNS (NSD) transport for Circle Mesh — same-LAN WiFi peer discovery.
 *
 * <p>Advertises this device on the local network as {@code _circlemesh._tcp}
 * and listens for other devices doing the same. Once a peer is resolved,
 * its IP address and port are reported to the {@link PeerDiscoveryListener}.
 *
 * <p>Data exchange uses a TCP server on port {@value #MESH_PORT} with the
 * same 4-byte length-prefixed framing as {@link WifiDirectTransport}.
 *
 * <p>This transport works on any network where mDNS multicast is allowed
 * (home WiFi, USB tethering, etc.).
 */
public class MdnsTransport extends MeshTransport {

    private static final String TAG = "MeshMdnsTransport";

    /** TCP port for Circle Mesh data over LAN. */
    static final int MESH_PORT = 8723;

    private static final String SERVICE_TYPE = "_circlemesh._tcp";

    private final Context    mContext;
    private final String     mDeviceId;
    private final String     mCapabilities;

    private NsdManager       mNsdManager;
    private NsdManager.RegistrationListener  mRegListener;
    private NsdManager.DiscoveryListener     mDiscoveryListenerNsd;

    private ServerSocket     mServerSocket;
    private final ExecutorService mExecutor = Executors.newCachedThreadPool();
    private final AtomicBoolean   mRunning  = new AtomicBoolean(false);
    private volatile boolean      mRegistered = false;

    // ── Constructor ───────────────────────────────────────────────────────────

    /**
     * @param context      Application context.
     * @param deviceId     16-char hex device ID to advertise in service name.
     * @param capabilities Comma-separated capability string (e.g. "OTA,MSG").
     */
    public MdnsTransport(Context context, String deviceId, String capabilities) {
        mContext      = context;
        mDeviceId     = deviceId;
        mCapabilities = capabilities;
    }

    // ── MeshTransport ─────────────────────────────────────────────────────────

    @Override
    public String getType() { return TYPE_MDNS; }

    @Override
    public boolean isActive() { return mRunning.get(); }

    @Override
    public void start() {
        if (!mRunning.compareAndSet(false, true)) return;
        Log.i(TAG, "Starting mDNS transport");

        mNsdManager = (NsdManager) mContext.getSystemService(Context.NSD_SERVICE);
        if (mNsdManager == null) {
            Log.e(TAG, "NsdManager not available");
            mRunning.set(false);
            return;
        }

        // Start TCP server
        mExecutor.submit(this::runServer);

        // Register NSD service
        registerService();

        // Discover peers
        startDiscovery();
    }

    @Override
    public void stop() {
        if (!mRunning.compareAndSet(true, false)) return;
        Log.i(TAG, "Stopping mDNS transport");

        if (mNsdManager != null) {
            if (mRegistered && mRegListener != null) {
                try { mNsdManager.unregisterService(mRegListener); } catch (Exception ignored) {}
                mRegistered = false;
            }
            if (mDiscoveryListenerNsd != null) {
                try { mNsdManager.stopServiceDiscovery(mDiscoveryListenerNsd); } catch (Exception ignored) {}
            }
        }

        try {
            if (mServerSocket != null) mServerSocket.close();
        } catch (IOException e) {
            Log.w(TAG, "Error closing server socket", e);
        }
    }

    @Override
    public boolean send(String address, byte[] frame) {
        // address format: "ip:port"
        String[] parts = address.split(":");
        if (parts.length < 2) {
            Log.w(TAG, "send: invalid address: " + address);
            return false;
        }
        String host = parts[0];
        int port;
        try {
            port = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            port = MESH_PORT;
        }

        final String h = host;
        final int    p = port;
        mExecutor.submit(() -> {
            try (Socket sock = new Socket()) {
                sock.connect(new InetSocketAddress(h, p), 5_000);
                DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
                dos.writeInt(frame.length);
                dos.write(frame);
                dos.flush();
                Log.d(TAG, "Sent " + frame.length + " bytes to " + h + ":" + p);
            } catch (IOException e) {
                Log.w(TAG, "send() failed to " + h + ":" + p + ": " + e.getMessage());
                if (mDiscoveryListener != null) mDiscoveryListener.onPeerLost(address);
            }
        });
        return true;
    }

    @Override
    public void announce(byte[] frame) {
        // mDNS: re-register service to refresh presence
        Log.d(TAG, "announce() — re-registering mDNS service");
        if (mRegistered && mNsdManager != null && mRegListener != null) {
            try { mNsdManager.unregisterService(mRegListener); } catch (Exception ignored) {}
            mRegistered = false;
        }
        registerService();
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
            if (mRunning.get()) Log.e(TAG, "Server socket error", e);
        }
    }

    private void handleInbound(Socket socket) {
        String from = socket.getInetAddress().getHostAddress() + ":" + MESH_PORT;
        try (DataInputStream dis = new DataInputStream(socket.getInputStream())) {
            while (mRunning.get()) {
                int len = dis.readInt();
                if (len <= 0 || len > 4 * 1024 * 1024) {
                    Log.w(TAG, "Invalid frame length " + len);
                    break;
                }
                byte[] frame = new byte[len];
                dis.readFully(frame);
                if (mMessageListener != null) {
                    mMessageListener.onMessageReceived(from, TYPE_MDNS, frame);
                }
            }
        } catch (IOException e) {
            Log.d(TAG, "Connection closed from " + from + ": " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    // ── NSD Registration ──────────────────────────────────────────────────────

    private void registerService() {
        NsdServiceInfo info = new NsdServiceInfo();
        // Service name is "CM-<deviceId>" — unique per device
        info.setServiceName("CM-" + (mDeviceId != null ? mDeviceId : "00000000"));
        info.setServiceType(SERVICE_TYPE);
        info.setPort(MESH_PORT);
        // Encode capability string as an attribute
        if (mCapabilities != null) {
            info.setAttribute("caps", mCapabilities);
        }

        mRegListener = new NsdManager.RegistrationListener() {
            @Override public void onRegistrationFailed(NsdServiceInfo si, int code) {
                Log.w(TAG, "NSD registration failed: " + code);
            }
            @Override public void onUnregistrationFailed(NsdServiceInfo si, int code) {
                Log.w(TAG, "NSD unregistration failed: " + code);
            }
            @Override public void onServiceRegistered(NsdServiceInfo si) {
                mRegistered = true;
                Log.i(TAG, "NSD service registered: " + si.getServiceName());
            }
            @Override public void onServiceUnregistered(NsdServiceInfo si) {
                mRegistered = false;
                Log.d(TAG, "NSD service unregistered");
            }
        };

        mNsdManager.registerService(info, NsdManager.PROTOCOL_DNS_SD, mRegListener);
    }

    // ── NSD Discovery ─────────────────────────────────────────────────────────

    private void startDiscovery() {
        mDiscoveryListenerNsd = new NsdManager.DiscoveryListener() {
            @Override public void onStartDiscoveryFailed(String type, int code) {
                Log.w(TAG, "Discovery start failed: " + code);
            }
            @Override public void onStopDiscoveryFailed(String type, int code) {
                Log.w(TAG, "Discovery stop failed: " + code);
            }
            @Override public void onDiscoveryStarted(String type) {
                Log.i(TAG, "NSD discovery started: " + type);
            }
            @Override public void onDiscoveryStopped(String type) {
                Log.d(TAG, "NSD discovery stopped");
            }
            @Override public void onServiceFound(NsdServiceInfo si) {
                Log.d(TAG, "NSD service found: " + si.getServiceName());
                // Skip ourselves
                String name = si.getServiceName();
                if (name != null && name.equals("CM-" + mDeviceId)) return;
                mNsdManager.resolveService(si, buildResolveListener());
            }
            @Override public void onServiceLost(NsdServiceInfo si) {
                Log.d(TAG, "NSD service lost: " + si.getServiceName());
                if (mDiscoveryListener != null) {
                    // Use service name as address since we may not have IP at this point
                    mDiscoveryListener.onPeerLost(si.getServiceName());
                }
            }
        };

        mNsdManager.discoverServices(SERVICE_TYPE,
                NsdManager.PROTOCOL_DNS_SD, mDiscoveryListenerNsd);
    }

    private NsdManager.ResolveListener buildResolveListener() {
        return new NsdManager.ResolveListener() {
            @Override public void onResolveFailed(NsdServiceInfo si, int code) {
                Log.w(TAG, "NSD resolve failed for " + si.getServiceName() + ": " + code);
            }
            @Override public void onServiceResolved(NsdServiceInfo si) {
                String host = si.getHost() != null ? si.getHost().getHostAddress() : null;
                int    port = si.getPort();
                String name = si.getServiceName(); // "CM-<deviceId>"

                Log.d(TAG, "NSD resolved: " + name + " -> " + host + ":" + port);

                if (host == null || host.isEmpty()) return;

                // Extract device ID from service name "CM-<16charHex>"
                String deviceId = (name != null && name.startsWith("CM-"))
                        ? name.substring(3) : "unknown";

                String capsAttr = si.getAttributes() != null ? null : null;
                // getAttribute returns byte[] in API 27+; read as UTF-8
                try {
                    byte[] capsBytes = si.getAttributes().get("caps");
                    if (capsBytes != null) capsAttr = new String(capsBytes, "UTF-8");
                } catch (Exception ignored) {}

                if (mDiscoveryListener != null) {
                    mDiscoveryListener.onPeerDiscovered(
                            deviceId,
                            host + ":" + port,
                            port,
                            TYPE_MDNS,
                            capsAttr);
                }
            }
        };
    }
}
