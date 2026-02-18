/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.mesh;

/**
 * Public Binder interface for the Circle Mesh Network service.
 *
 * Obtain via:
 * <pre>
 *   IBinder binder = ServiceManager.getService("circle.mesh");
 *   ICircleMeshService mesh = ICircleMeshService.Stub.asInterface(binder);
 * </pre>
 *
 * All methods may be called from any thread. Delivery callbacks are NOT
 * provided through this AIDL interface — apps should use the broadcast
 * {@code za.co.circleos.mesh.action.MESSAGE_RECEIVED} instead.
 */
interface ICircleMeshService {

    /**
     * Sends a message to a remote device via the mesh network.
     *
     * If the device is not currently reachable, the message is stored for
     * later delivery (store-and-forward, TTL 7 days).
     *
     * @param recipientDeviceId 16-char hex rotating device ID of the target.
     * @param payload           Raw message payload bytes (max 64 KB).
     * @param msgType           Message type from MeshProtocol (e.g. 0x10 = MSG_TEXT).
     * @return true if the message was dispatched or queued successfully.
     */
    boolean sendMessage(String recipientDeviceId, in byte[] payload, int msgType);

    /**
     * Returns the number of peers currently in the peer table.
     */
    int getPeerCount();

    /**
     * Returns true if the mesh stack has been started and transports are active.
     */
    boolean isRunning();

    /**
     * Returns the current rotating device ID for this device (16-char hex, 8 bytes).
     * Changes every 24 hours for privacy.
     */
    String getDeviceId();
}
