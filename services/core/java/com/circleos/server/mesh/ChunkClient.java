/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.util.Slog;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Client-side chunk downloader for the CircleOS mesh OTA system.
 *
 * Connects to a peer's TCP port (default {@link PeerDiscovery#MESH_PORT}),
 * issues a single request, reads the response, and closes the connection.
 * All operations are stateless (one request per TCP connection).
 *
 * Connect timeout: 5 seconds.
 * Read (socket SO_TIMEOUT) timeout: 30 seconds.
 *
 * Every method returns null on any failure — no exceptions are propagated.
 */
public final class ChunkClient {

    private static final String TAG = "ChunkClient";

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS    = 30_000;

    // Private constructor — static utility class
    private ChunkClient() {}

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Connects to the peer, sends a DISCOVER message, and reads the CHUNK_MAP
     * response to learn which chunks the peer holds.
     *
     * @param peer The peer to query.
     * @return The chunk availability bitmap, or {@code null} on any failure.
     */
    public static byte[] requestChunkMap(PeerDiscovery.PeerInfo peer) {
        if (peer == null) return null;
        return staticRequestChunkMap(peer.address, peer.port, peer.version);
    }

    /**
     * Static variant used by {@link PeerDiscovery} for probing before a full
     * {@link PeerDiscovery.PeerInfo} object exists.
     *
     * @param address IP address or hostname of the peer.
     * @param port    TCP port (normally {@link PeerDiscovery#MESH_PORT}).
     * @param version OTA version string to query.
     * @return The chunk availability bitmap, or {@code null} on failure.
     */
    static byte[] staticRequestChunkMap(String address, int port, String version) {
        if (address == null || version == null) return null;

        try (Socket sock = openSocket(address, port)) {
            if (sock == null) return null;

            OutputStream out = sock.getOutputStream();
            InputStream  in  = sock.getInputStream();

            // Send DISCOVER
            byte[] discoverFrame = MeshProtocol.buildDiscover(version);
            out.write(discoverFrame);
            out.flush();

            // Read response — expect CHUNK_MAP
            MeshProtocol.Message response = MeshProtocol.decode(in);
            if (response.type != MeshProtocol.MSG_CHUNK_MAP) {
                Slog.w(TAG, "requestChunkMap: unexpected response type 0x"
                        + Integer.toHexString(response.type) + " from " + address);
                return null;
            }

            byte[] bitmap = MeshProtocol.parseBitmap(response.payload);
            if (bitmap == null) {
                Slog.w(TAG, "requestChunkMap: malformed CHUNK_MAP payload from " + address);
            }
            return bitmap;

        } catch (IOException e) {
            Slog.d(TAG, "requestChunkMap: " + address + ":" + port + " — " + e.getMessage());
            return null;
        } catch (Exception e) {
            Slog.w(TAG, "requestChunkMap: unexpected error from " + address, e);
            return null;
        }
    }

    /**
     * Downloads a single chunk from the given peer.
     *
     * Connects to the peer, sends a CHUNK_REQUEST for {@code chunkIndex},
     * reads the CHUNK_DATA response, and returns the raw payload bytes.
     *
     * @param peer       The peer to download from.
     * @param chunkIndex Zero-based chunk index to request.
     * @return The raw chunk bytes, or {@code null} on any failure.
     */
    public static byte[] downloadChunk(PeerDiscovery.PeerInfo peer, int chunkIndex) {
        if (peer == null || chunkIndex < 0) return null;

        try (Socket sock = openSocket(peer.address, peer.port)) {
            if (sock == null) return null;

            OutputStream out = sock.getOutputStream();
            InputStream  in  = sock.getInputStream();

            // Send CHUNK_REQUEST
            byte[] requestFrame = MeshProtocol.buildChunkRequest(chunkIndex);
            out.write(requestFrame);
            out.flush();

            // Read response — expect CHUNK_DATA
            MeshProtocol.Message response = MeshProtocol.decode(in);
            if (response.type != MeshProtocol.MSG_CHUNK_DATA) {
                Slog.w(TAG, "downloadChunk: unexpected response type 0x"
                        + Integer.toHexString(response.type)
                        + " for chunk " + chunkIndex + " from " + peer.address);
                return null;
            }

            Object[] parsed = MeshProtocol.parseChunkData(response.payload);
            if (parsed == null) {
                Slog.w(TAG, "downloadChunk: malformed CHUNK_DATA payload from " + peer.address);
                return null;
            }

            int receivedIndex = (Integer) parsed[0];
            byte[] data       = (byte[]) parsed[1];

            if (receivedIndex != chunkIndex) {
                Slog.w(TAG, "downloadChunk: index mismatch — requested=" + chunkIndex
                        + " received=" + receivedIndex + " from " + peer.address);
                return null;
            }

            Slog.d(TAG, "downloadChunk: chunk=" + chunkIndex
                    + " size=" + (data != null ? data.length : 0)
                    + " from " + peer.address);
            return data;

        } catch (IOException e) {
            Slog.d(TAG, "downloadChunk: chunk=" + chunkIndex
                    + " " + peer.address + ":" + peer.port + " — " + e.getMessage());
            return null;
        } catch (Exception e) {
            Slog.w(TAG, "downloadChunk: unexpected error for chunk " + chunkIndex
                    + " from " + peer.address, e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Opens a TCP socket to the given address and port with configured timeouts.
     *
     * @return A connected {@link Socket}, or {@code null} if the connection
     *         could not be established.
     */
    private static Socket openSocket(String address, int port) {
        try {
            Socket sock = new Socket();
            sock.setSoTimeout(READ_TIMEOUT_MS);
            sock.connect(new InetSocketAddress(address, port), CONNECT_TIMEOUT_MS);
            return sock;
        } catch (IOException e) {
            Slog.d(TAG, "openSocket: could not connect to " + address + ":" + port
                    + " — " + e.getMessage());
            return null;
        }
    }
}
