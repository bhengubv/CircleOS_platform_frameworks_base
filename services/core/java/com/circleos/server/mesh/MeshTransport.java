/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

/**
 * Abstract base class for all Circle Mesh transport backends.
 *
 * <p>Concrete implementations must handle:
 * <ul>
 *   <li>Peer discovery / advertisement specific to the transport medium.</li>
 *   <li>Establishing outbound connections and accepting inbound connections.</li>
 *   <li>Framing messages and handing them to the registered {@link MessageListener}.</li>
 *   <li>Reporting newly discovered peers via the registered {@link PeerDiscoveryListener}.</li>
 * </ul>
 *
 * <p>Available transports:
 * <ul>
 *   <li>{@link WifiDirectTransport} — TCP port 9847 over WiFi P2P</li>
 *   <li>{@link BluetoothLeTransport} — BLE advertisement only (discovery only, no data)</li>
 *   <li>{@link MdnsTransport} — TCP port 8723 over LAN mDNS (_circlemesh._tcp)</li>
 * </ul>
 */
public abstract class MeshTransport {

    // ── Transport type constants ───────────────────────────────────────────────

    public static final String TYPE_WIFI_DIRECT = "WIFI_DIRECT";
    public static final String TYPE_BT_LE       = "BT_LE";
    public static final String TYPE_MDNS        = "MDNS";
    public static final String TYPE_USB         = "USB";

    // ── Listener interfaces ───────────────────────────────────────────────────

    /**
     * Delivered when a complete mesh frame is received from any peer.
     */
    public interface MessageListener {
        /**
         * @param from      Transport-layer address of the sender (IP:port or BT address).
         * @param transport Transport type constant ({@code TYPE_*}).
         * @param frame     Complete encoded mesh frame (header + body).
         */
        void onMessageReceived(String from, String transport, byte[] frame);
    }

    /**
     * Delivered when a peer is discovered or lost on this transport.
     */
    public interface PeerDiscoveryListener {
        /**
         * Called when a new peer is found.
         *
         * @param deviceId   8-char hex device ID extracted from the discovery record.
         * @param address    IP address or BT address.
         * @param port       TCP port (0 for BLE which does not carry data).
         * @param transport  Transport type constant.
         * @param caps       Comma-separated capability string from TXT record, or null.
         */
        void onPeerDiscovered(String deviceId, String address, int port,
                String transport, String caps);

        /**
         * Called when a previously discovered peer is no longer visible.
         *
         * @param address Transport-layer address that has gone away.
         */
        void onPeerLost(String address);
    }

    // ── State ─────────────────────────────────────────────────────────────────

    protected MessageListener       mMessageListener;
    protected PeerDiscoveryListener mDiscoveryListener;

    // ── Listener registration ─────────────────────────────────────────────────

    public void setMessageListener(MessageListener listener) {
        mMessageListener = listener;
    }

    public void setPeerDiscoveryListener(PeerDiscoveryListener listener) {
        mDiscoveryListener = listener;
    }

    // ── Abstract transport API ────────────────────────────────────────────────

    /**
     * Starts this transport: begins advertising and listening for peers.
     * Must be called before {@link #send}.
     */
    public abstract void start();

    /**
     * Stops this transport and releases all resources.
     */
    public abstract void stop();

    /**
     * Sends a mesh frame to the specified peer address.
     *
     * @param address Transport-layer address (IP:port, BT MAC, etc.).
     * @param frame   Encoded mesh frame bytes.
     * @return true if the frame was handed off to the transport successfully.
     *         false on connection error or if the transport is inactive.
     */
    public abstract boolean send(String address, byte[] frame);

    /**
     * Broadcasts an ANNOUNCE frame to all reachable peers on this transport.
     * Transport determines how (e.g., multicast, WiFi P2P service record update).
     *
     * @param frame Encoded ANNOUNCE frame.
     */
    public abstract void announce(byte[] frame);

    /**
     * @return The transport type constant (e.g. {@link #TYPE_WIFI_DIRECT}).
     */
    public abstract String getType();

    /**
     * @return true if this transport is currently started and capable of sending/receiving.
     */
    public abstract boolean isActive();
}
