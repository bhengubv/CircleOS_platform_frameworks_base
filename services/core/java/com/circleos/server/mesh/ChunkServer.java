/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.util.Slog;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * TCP server that serves OTA chunks to peer devices over the mesh.
 *
 * Listens on port {@link PeerDiscovery#MESH_PORT} (9847).
 *
 * Supported request types (per connection):
 *   DISCOVER      → responds with CHUNK_MAP (our chunk availability bitmap)
 *   CHUNK_REQUEST → responds with CHUNK_DATA for the requested index
 *
 * Connections are stateless — one request is handled per TCP connection.
 *
 * Sharing eligibility:
 *   Chunks are served only when BOTH of the following are true:
 *   - Device is connected to a WiFi network.
 *   - Device is charging OR battery level is above 50%.
 *
 * Max concurrent connections: 5.
 */
public final class ChunkServer {

    private static final String TAG = "ChunkServer";

    /** Maximum number of simultaneously-served client connections. */
    private static final int MAX_CONCURRENT = 5;

    /** Minimum battery percentage required to serve chunks when not charging. */
    private static final int MIN_BATTERY_PCT = 50;

    private final ChunkManager   mChunkManager;
    private final Context        mContext;
    private final ExecutorService mThreadPool;
    private final AtomicBoolean  mRunning = new AtomicBoolean(false);

    private ServerSocket mServerSocket;
    private Thread       mAcceptThread;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * @param context      System context (used for battery/connectivity checks).
     * @param chunkManager The chunk store to serve data from.
     */
    public ChunkServer(Context context, ChunkManager chunkManager) {
        mContext      = context;
        mChunkManager = chunkManager;
        mThreadPool   = Executors.newFixedThreadPool(MAX_CONCURRENT);
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /**
     * Opens the server socket and starts accepting connections in a background
     * thread.
     *
     * @throws IOException If the server socket cannot be bound.
     */
    public synchronized void start() throws IOException {
        if (mRunning.get()) {
            Slog.w(TAG, "start() called while already running");
            return;
        }

        mServerSocket = new ServerSocket(PeerDiscovery.MESH_PORT);
        mRunning.set(true);

        mAcceptThread = new Thread(this::acceptLoop, "ChunkServer-Accept");
        mAcceptThread.setDaemon(true);
        mAcceptThread.start();

        Slog.i(TAG, "ChunkServer started on port " + PeerDiscovery.MESH_PORT);
    }

    /**
     * Closes the server socket and stops accepting new connections.
     * In-flight connections are allowed to complete naturally.
     */
    public synchronized void stop() {
        if (!mRunning.compareAndSet(true, false)) return;

        try {
            if (mServerSocket != null) mServerSocket.close();
        } catch (IOException e) {
            Slog.w(TAG, "stop: error closing server socket", e);
        }
        mServerSocket  = null;
        mAcceptThread  = null;
        Slog.i(TAG, "ChunkServer stopped");
    }

    // -------------------------------------------------------------------------
    // Accept loop
    // -------------------------------------------------------------------------

    private void acceptLoop() {
        while (mRunning.get()) {
            try {
                Socket client = mServerSocket.accept();
                mThreadPool.execute(() -> handleConnection(client));
            } catch (IOException e) {
                if (mRunning.get()) {
                    Slog.w(TAG, "acceptLoop: accept error", e);
                }
                // If mRunning is false, the socket was intentionally closed.
            }
        }
    }

    // -------------------------------------------------------------------------
    // Connection handler
    // -------------------------------------------------------------------------

    /**
     * Handles a single client connection:
     *   1. Checks sharing eligibility (WiFi + battery).
     *   2. Reads one MeshProtocol message from the client.
     *   3. Responds appropriately (CHUNK_MAP or CHUNK_DATA).
     *   4. Closes the socket.
     */
    private void handleConnection(Socket client) {
        String remoteAddr = client.getRemoteSocketAddress() != null
                ? client.getRemoteSocketAddress().toString() : "unknown";
        Slog.d(TAG, "Connection from " + remoteAddr);

        try (Socket s = client) {
            s.setSoTimeout(10_000); // 10 s read timeout per connection

            if (!isSharingEligible()) {
                Slog.d(TAG, "handleConnection: not eligible to serve, closing " + remoteAddr);
                return;
            }

            InputStream  in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            MeshProtocol.Message msg;
            try {
                msg = MeshProtocol.decode(in);
            } catch (IOException e) {
                Slog.d(TAG, "handleConnection: bad frame from " + remoteAddr
                        + ": " + e.getMessage());
                return;
            }

            switch (msg.type) {
                case MeshProtocol.MSG_DISCOVER:
                    handleDiscover(out, msg, remoteAddr);
                    break;

                case MeshProtocol.MSG_CHUNK_REQUEST:
                    handleChunkRequest(out, msg, remoteAddr);
                    break;

                default:
                    Slog.w(TAG, "handleConnection: unexpected message type 0x"
                            + Integer.toHexString(msg.type) + " from " + remoteAddr);
                    break;
            }

        } catch (IOException e) {
            Slog.w(TAG, "handleConnection: I/O error with " + remoteAddr, e);
        }
    }

    // -------------------------------------------------------------------------
    // Message handlers
    // -------------------------------------------------------------------------

    /** Responds to a DISCOVER request with our CHUNK_MAP. */
    private void handleDiscover(OutputStream out, MeshProtocol.Message msg,
            String remoteAddr) throws IOException {
        String version = MeshProtocol.parseVersion(msg.payload);
        if (version == null) {
            Slog.w(TAG, "handleDiscover: malformed payload from " + remoteAddr);
            return;
        }

        byte[] bitmap = mChunkManager.getChunkBitmap();
        byte[] response = MeshProtocol.buildChunkMap(version, bitmap);
        out.write(response);
        out.flush();

        Slog.d(TAG, "handleDiscover: sent CHUNK_MAP to " + remoteAddr
                + " bitmap.length=" + bitmap.length);
    }

    /** Responds to a CHUNK_REQUEST with CHUNK_DATA. */
    private void handleChunkRequest(OutputStream out, MeshProtocol.Message msg,
            String remoteAddr) throws IOException {
        int chunkIndex = MeshProtocol.parseChunkIndex(msg.payload);
        if (chunkIndex < 0) {
            Slog.w(TAG, "handleChunkRequest: malformed payload from " + remoteAddr);
            return;
        }

        if (!mChunkManager.hasChunk(chunkIndex)) {
            Slog.d(TAG, "handleChunkRequest: chunk " + chunkIndex
                    + " not available, sending empty CHUNK_DATA to " + remoteAddr);
            // Send an empty CHUNK_DATA to signal "I don't have it"
            out.write(MeshProtocol.buildChunkData(chunkIndex, new byte[0]));
            out.flush();
            return;
        }

        byte[] data = mChunkManager.getChunk(chunkIndex);
        if (data == null) {
            Slog.e(TAG, "handleChunkRequest: getChunk(" + chunkIndex
                    + ") returned null despite hasChunk=true");
            out.write(MeshProtocol.buildChunkData(chunkIndex, new byte[0]));
            out.flush();
            return;
        }

        out.write(MeshProtocol.buildChunkData(chunkIndex, data));
        out.flush();

        Slog.d(TAG, "handleChunkRequest: served chunk=" + chunkIndex
                + " size=" + data.length + " to " + remoteAddr);
    }

    // -------------------------------------------------------------------------
    // Sharing eligibility
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} when the device is allowed to serve chunks:
     *   - Must be connected to WiFi.
     *   - Must be charging OR battery level > 50%.
     */
    private boolean isSharingEligible() {
        return isOnWifi() && (isCharging() || getBatteryLevel() > MIN_BATTERY_PCT);
    }

    /** Returns {@code true} if the device currently has a WiFi network connection. */
    private boolean isOnWifi() {
        ConnectivityManager cm =
                (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;
        Network active = cm.getActiveNetwork();
        if (active == null) return false;
        NetworkCapabilities caps = cm.getNetworkCapabilities(active);
        return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
    }

    /** Returns {@code true} if the device is currently plugged in and charging. */
    private boolean isCharging() {
        IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent status = mContext.registerReceiver(null, filter);
        if (status == null) return false;
        int plugged = status.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
        return plugged == BatteryManager.BATTERY_PLUGGED_AC
                || plugged == BatteryManager.BATTERY_PLUGGED_USB
                || plugged == BatteryManager.BATTERY_PLUGGED_WIRELESS;
    }

    /**
     * Returns the current battery charge level as a percentage (0–100),
     * or 0 if the level cannot be determined.
     */
    private int getBatteryLevel() {
        IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent status = mContext.registerReceiver(null, filter);
        if (status == null) return 0;
        int level = status.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = status.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
        if (level < 0 || scale <= 0) return 0;
        return (int) ((level * 100f) / scale);
    }
}
