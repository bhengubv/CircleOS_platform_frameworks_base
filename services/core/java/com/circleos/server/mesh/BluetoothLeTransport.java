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
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.os.ParcelUuid;
import android.util.Log;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Bluetooth LE transport for Circle Mesh (discovery-only).
 *
 * <p>Advertises the device's presence via BLE manufacturer-specific data
 * containing the current device ID. Data transfer is NOT performed over BLE;
 * it is used purely to announce presence so another transport (WiFi Direct or
 * mDNS) can be used for the actual message exchange.
 *
 * <p>Service UUID: {@value #MESH_UUID_STR} (custom 128-bit UUID based on 0x1823).
 *
 * <p>Manufacturer data format (10 bytes):
 * <pre>
 *   [0..7]  — 8-byte device ID (hex decoded from 16-char string)
 *   [8..9]  — capability flags (reserved, 0 for now)
 * </pre>
 *
 * <p>Battery policy: advertising is suppressed when battery level < 20%.
 */
public class BluetoothLeTransport extends MeshTransport {

    private static final String TAG = "MeshBleTransport";

    /** Custom UUID for Circle Mesh BLE service. Based on 0x1823. */
    static final String MESH_UUID_STR = "00001823-0000-1000-8000-00805f9b34fb";
    static final ParcelUuid MESH_UUID = ParcelUuid.fromString(MESH_UUID_STR);

    /**
     * GATT characteristic UUID for the WiFi-IP endpoint (0x1824).
     * Value format: UTF-8 string "address:port" (e.g. "192.168.49.1:9847").
     * Readable by GATT clients to bootstrap a TCP mesh connection.
     */
    static final UUID WIFI_IP_CHAR_UUID = UUID.fromString("00001824-0000-1000-8000-00805f9b34fb");

    /** Manufacturer ID used in BLE advertisement (0xC1CE = CircleOS). */
    static final int MANUFACTURER_ID = 0xC1CE;

    private final Context         mContext;
    private final String          mDeviceId;   // 16-char hex (8 bytes)

    private BluetoothAdapter      mAdapter;
    private BluetoothLeAdvertiser mAdvertiser;
    private BluetoothLeScanner    mScanner;
    private BluetoothGattServer   mGattServer;
    private final AtomicBoolean   mRunning     = new AtomicBoolean(false);
    private final AtomicBoolean   mAdvertising  = new AtomicBoolean(false);

    /** Current local WiFi endpoint, set by CircleMeshService when its TCP server is ready. */
    private volatile String mLocalWifiAddress = "";
    private volatile int    mLocalWifiPort    = 9847;

    // ── Constructor ───────────────────────────────────────────────────────────

    /**
     * @param context  Application context.
     * @param deviceId 16-char hex device ID to encode in BLE manufacturer data.
     */
    public BluetoothLeTransport(Context context, String deviceId) {
        mContext  = context;
        mDeviceId = deviceId;
    }

    /**
     * Updates the WiFi endpoint that GATT clients will read from the WiFi-IP
     * characteristic. Call this whenever the local TCP server address changes
     * (e.g., after WiFi Direct group formation or mDNS socket bind).
     *
     * @param address  Local IP address (WiFi Direct or LAN), never null.
     * @param port     TCP port (typically 9847 for WifiDirect, 8723 for mDNS).
     */
    public void setLocalWifiEndpoint(String address, int port) {
        mLocalWifiAddress = address != null ? address : "";
        mLocalWifiPort    = port;
        Log.d(TAG, "Local WiFi endpoint updated: " + mLocalWifiAddress + ":" + mLocalWifiPort);
    }

    // ── MeshTransport ─────────────────────────────────────────────────────────

    @Override
    public String getType() { return TYPE_BT_LE; }

    @Override
    public boolean isActive() { return mRunning.get(); }

    @Override
    public void start() {
        if (!mRunning.compareAndSet(false, true)) return;

        BluetoothManager bm = (BluetoothManager) mContext.getSystemService(Context.BLUETOOTH_SERVICE);
        if (bm == null) {
            Log.w(TAG, "BluetoothManager not available");
            mRunning.set(false);
            return;
        }
        mAdapter = bm.getAdapter();
        if (mAdapter == null || !mAdapter.isEnabled()) {
            Log.w(TAG, "Bluetooth not enabled");
            mRunning.set(false);
            return;
        }

        mAdvertiser = mAdapter.getBluetoothLeAdvertiser();
        mScanner    = mAdapter.getBluetoothLeScanner();

        startGattServer(bm);
        startAdvertising();
        startScanning();
        Log.i(TAG, "BLE transport started, deviceId=" + mDeviceId);
    }

    @Override
    public void stop() {
        if (!mRunning.compareAndSet(true, false)) return;
        Log.i(TAG, "Stopping BLE transport");
        stopAdvertising();
        stopScanning();
        stopGattServer();
    }

    /**
     * BLE is discovery-only — data transfer is not supported.
     * Always returns false.
     */
    @Override
    public boolean send(String address, byte[] frame) {
        Log.w(TAG, "send() called on BLE transport (discovery-only) — ignored");
        return false;
    }

    /** BLE announce: refresh the advertisement with current device ID. */
    @Override
    public void announce(byte[] frame) {
        if (!mRunning.get()) return;
        stopAdvertising();
        startAdvertising();
    }

    // ── Advertising ───────────────────────────────────────────────────────────

    private void startAdvertising() {
        if (mAdvertiser == null) return;

        byte[] manufacturerData = buildManufacturerData();

        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
                .setConnectable(true) // allow GATT clients to read WiFi-IP characteristic
                .setTimeout(0) // advertise indefinitely
                .build();

        AdvertiseData data = new AdvertiseData.Builder()
                .addServiceUuid(MESH_UUID)
                .addManufacturerData(MANUFACTURER_ID, manufacturerData)
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .build();

        mAdvertiser.startAdvertising(settings, data, mAdvertiseCallback);
    }

    private void stopAdvertising() {
        if (mAdvertiser != null && mAdvertising.get()) {
            try {
                mAdvertiser.stopAdvertising(mAdvertiseCallback);
            } catch (Exception e) {
                Log.w(TAG, "stopAdvertising error", e);
            }
            mAdvertising.set(false);
        }
    }

    private final AdvertiseCallback mAdvertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            mAdvertising.set(true);
            Log.d(TAG, "BLE advertising started");
        }
        @Override
        public void onStartFailure(int errorCode) {
            Log.w(TAG, "BLE advertising failed: errorCode=" + errorCode);
        }
    };

    // ── Scanning ──────────────────────────────────────────────────────────────

    private void startScanning() {
        if (mScanner == null) return;

        ScanFilter filter = new ScanFilter.Builder()
                .setServiceUuid(MESH_UUID)
                .build();

        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                .build();

        mScanner.startScan(Collections.singletonList(filter), settings, mScanCallback);
        Log.d(TAG, "BLE scanning started");
    }

    private void stopScanning() {
        if (mScanner != null) {
            try {
                mScanner.stopScan(mScanCallback);
            } catch (Exception e) {
                Log.w(TAG, "stopScan error", e);
            }
        }
    }

    private final ScanCallback mScanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            handleScanResult(result);
        }

        @Override
        public void onScanFailed(int errorCode) {
            Log.w(TAG, "BLE scan failed: errorCode=" + errorCode);
        }
    };

    private void handleScanResult(ScanResult result) {
        ScanRecord record = result.getScanRecord();
        if (record == null) return;

        byte[] mfData = record.getManufacturerSpecificData(MANUFACTURER_ID);
        if (mfData == null || mfData.length < 8) return;

        // Extract 8-byte device ID
        final String discoveredId = MeshCrypto.bytesToHex(mfData, 0, 8);
        final String btAddress    = result.getDevice().getAddress();

        Log.d(TAG, "BLE peer discovered: id=" + discoveredId + " addr=" + btAddress
                + " — connecting GATT to read WiFi-IP");

        // Connect as GATT client to read the WiFi-IP characteristic.
        // On success: report peer with real TCP address so WifiDirect/mDNS can connect.
        // On failure: report peer with port=0 (BLE-only, no TCP known).
        result.getDevice().connectGatt(mContext, /*autoConnect=*/false, new BluetoothGattCallback() {
            @Override
            public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    gatt.discoverServices();
                } else {
                    Log.d(TAG, "GATT client disconnected from " + btAddress + " state=" + newState);
                    gatt.close();
                    reportPeerFallback(discoveredId, btAddress);
                }
            }

            @Override
            public void onServicesDiscovered(BluetoothGatt gatt, int status) {
                BluetoothGattService svc = gatt.getService(UUID.fromString(MESH_UUID_STR));
                if (svc == null) {
                    gatt.close();
                    reportPeerFallback(discoveredId, btAddress);
                    return;
                }
                BluetoothGattCharacteristic c = svc.getCharacteristic(WIFI_IP_CHAR_UUID);
                if (c == null || !gatt.readCharacteristic(c)) {
                    gatt.close();
                    reportPeerFallback(discoveredId, btAddress);
                }
            }

            @Override
            public void onCharacteristicRead(BluetoothGatt gatt,
                    BluetoothGattCharacteristic c, int status) {
                gatt.disconnect();
                gatt.close();
                if (status == BluetoothGatt.GATT_SUCCESS
                        && WIFI_IP_CHAR_UUID.equals(c.getUuid())) {
                    String value = new String(c.getValue(), StandardCharsets.UTF_8).trim();
                    int colon = value.lastIndexOf(':');
                    if (colon > 0) {
                        String ip   = value.substring(0, colon);
                        int    port = 0;
                        try { port = Integer.parseInt(value.substring(colon + 1)); }
                        catch (NumberFormatException ignored) {}
                        if (!ip.isEmpty() && port > 0) {
                            Log.i(TAG, "GATT WiFi-IP resolved: " + discoveredId
                                    + " → " + ip + ":" + port);
                            if (mDiscoveryListener != null) {
                                mDiscoveryListener.onPeerDiscovered(
                                        discoveredId, ip, port, TYPE_WIFI_DIRECT, null);
                            }
                            return;
                        }
                    }
                }
                reportPeerFallback(discoveredId, btAddress);
            }
        });
    }

    /** Reports a peer with port=0 when GATT WiFi-IP read fails or peer has no TCP server. */
    private void reportPeerFallback(String deviceId, String btAddress) {
        if (mDiscoveryListener != null) {
            mDiscoveryListener.onPeerDiscovered(deviceId, btAddress, 0, TYPE_BT_LE, null);
        }
    }

    // ── GATT server (WiFi-IP characteristic) ──────────────────────────────────

    /**
     * Opens a GATT server hosting the Circle Mesh service with a single
     * readable characteristic (WIFI_IP_CHAR_UUID) that returns the current
     * local WiFi-Direct/mDNS address and port in "ip:port" format.
     */
    private void startGattServer(BluetoothManager bm) {
        try {
            mGattServer = bm.openGattServer(mContext, mGattServerCallback);
            if (mGattServer == null) { Log.w(TAG, "openGattServer failed"); return; }

            BluetoothGattService svc = new BluetoothGattService(
                    UUID.fromString(MESH_UUID_STR),
                    BluetoothGattService.SERVICE_TYPE_PRIMARY);

            BluetoothGattCharacteristic wifiIpChar = new BluetoothGattCharacteristic(
                    WIFI_IP_CHAR_UUID,
                    BluetoothGattCharacteristic.PROPERTY_READ,
                    BluetoothGattCharacteristic.PERMISSION_READ);
            wifiIpChar.setValue((mLocalWifiAddress + ":" + mLocalWifiPort)
                    .getBytes(StandardCharsets.UTF_8));

            svc.addCharacteristic(wifiIpChar);
            mGattServer.addService(svc);
            Log.i(TAG, "GATT server opened with WiFi-IP characteristic");
        } catch (Exception e) {
            Log.e(TAG, "Failed to start GATT server", e);
        }
    }

    private void stopGattServer() {
        if (mGattServer != null) {
            try { mGattServer.close(); } catch (Exception ignored) {}
            mGattServer = null;
        }
    }

    private final BluetoothGattServerCallback mGattServerCallback = new BluetoothGattServerCallback() {
        @Override
        public void onConnectionStateChange(BluetoothDevice device, int status, int newState) {
            Log.d(TAG, "GATT server: device " + device.getAddress()
                    + (newState == BluetoothProfile.STATE_CONNECTED ? " connected" : " disconnected"));
        }

        @Override
        public void onCharacteristicReadRequest(BluetoothDevice device, int requestId,
                int offset, BluetoothGattCharacteristic characteristic) {
            if (WIFI_IP_CHAR_UUID.equals(characteristic.getUuid())) {
                byte[] raw = (mLocalWifiAddress + ":" + mLocalWifiPort)
                        .getBytes(StandardCharsets.UTF_8);
                byte[] response = (offset < raw.length)
                        ? Arrays.copyOfRange(raw, offset, raw.length)
                        : new byte[0];
                mGattServer.sendResponse(device, requestId,
                        BluetoothGatt.GATT_SUCCESS, offset, response);
            } else {
                mGattServer.sendResponse(device, requestId,
                        BluetoothGatt.GATT_FAILURE, 0, null);
            }
        }
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Encodes the local device ID into 10-byte manufacturer data. */
    private byte[] buildManufacturerData() {
        byte[] data = new byte[10];
        // Parse 16-char hex device ID into 8 bytes
        String id = mDeviceId != null ? mDeviceId : "0000000000000000";
        for (int i = 0; i < 8 && i * 2 + 1 < id.length(); i++) {
            data[i] = (byte) Integer.parseInt(id.substring(i * 2, i * 2 + 2), 16);
        }
        // Bytes 8-9: capability flags (reserved)
        data[8] = 0;
        data[9] = 0;
        return data;
    }
}
