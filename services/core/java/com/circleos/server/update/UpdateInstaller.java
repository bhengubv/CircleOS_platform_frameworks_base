/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.content.Context;
import android.os.PowerManager;
import android.os.UpdateEngine;
import android.os.UpdateEngineCallback;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Drives A/B seamless OTA installation via {@link UpdateEngine}.
 *
 * For a standard A/B device, UpdateEngine applies the payload in the background
 * against the inactive slot. When STATUS_UPDATED_NEED_REBOOT is received, we
 * trigger a normal reboot ({@link PowerManager#reboot(String)} with null) so the
 * bootloader switches to the newly flashed slot.
 *
 * The ZIP must contain:
 *   payload.bin              — the payload binary
 *   payload_properties.txt  — KEY=VALUE pairs including FILE_SIZE, FILE_HASH,
 *                             METADATA_SIZE, METADATA_HASH
 */
public class UpdateInstaller {

    private static final String TAG = "CircleUpdateInstaller";

    private static final String PAYLOAD_BINARY_FILE     = "payload.bin";
    private static final String PAYLOAD_PROPERTIES_FILE = "payload_properties.txt";

    // UpdateEngine status codes — used for human-readable logging
    private static final int STATUS_IDLE                    = 0;
    private static final int STATUS_CHECKING_FOR_UPDATE     = 1;
    private static final int STATUS_UPDATE_AVAILABLE        = 2;
    private static final int STATUS_DOWNLOADING             = 3;
    private static final int STATUS_VERIFYING               = 4;
    private static final int STATUS_FINALIZING              = 5;
    private static final int STATUS_UPDATED_NEED_REBOOT     = 6;
    private static final int STATUS_REPORTING_ERROR_EVENT   = 7;
    private static final int STATUS_ATTEMPTING_ROLLBACK     = 8;
    private static final int STATUS_DISABLED                = 9;

    private final Context      mContext;
    private final UpdateEngine mUpdateEngine;

    public UpdateInstaller(Context context) {
        mContext      = context;
        mUpdateEngine = new UpdateEngine();
    }

    /**
     * Applies an OTA payload directly from a URL with pre-computed header properties.
     *
     * @param payloadUrl         HTTPS URL to payload.bin (may use file:// for local files).
     * @param headerKeyValuePairs KEY=VALUE strings (FILE_SIZE, FILE_HASH, etc.).
     * @param callback           Receives status/progress events from UpdateEngine.
     */
    public void install(String payloadUrl, String[] headerKeyValuePairs,
            UpdateEngineCallback callback) {
        Log.i(TAG, "Installing from URL: " + payloadUrl);
        mUpdateEngine.bind(wrapCallback(callback));
        mUpdateEngine.applyPayload(payloadUrl, 0, 0, headerKeyValuePairs);
    }

    /**
     * Applies an OTA update from a locally downloaded ZIP file.
     *
     * Reads payload_properties.txt from the ZIP to determine payload offset and size,
     * then calls {@link UpdateEngine#applyPayload(String, long, long, String[])}.
     *
     * @param localFile The locally-downloaded OTA zip.
     * @param callback  Receives status/progress events from UpdateEngine.
     * @throws IOException if the ZIP cannot be read or required entries are missing.
     */
    public void install(File localFile, UpdateEngineCallback callback) throws IOException {
        Log.i(TAG, "Installing from local file: " + localFile.getAbsolutePath());

        if (!localFile.exists()) {
            throw new IOException("OTA file does not exist: " + localFile.getAbsolutePath());
        }

        long payloadOffset;
        long payloadSize;
        String[] properties;

        try (ZipFile zipFile = new ZipFile(localFile)) {
            // Read payload_properties.txt
            ZipEntry propsEntry = zipFile.getEntry(PAYLOAD_PROPERTIES_FILE);
            if (propsEntry == null) {
                throw new IOException("ZIP missing " + PAYLOAD_PROPERTIES_FILE);
            }
            properties = readProperties(zipFile, propsEntry);

            // Determine payload.bin offset and size within the ZIP
            ZipEntry payloadEntry = zipFile.getEntry(PAYLOAD_BINARY_FILE);
            if (payloadEntry == null) {
                throw new IOException("ZIP missing " + PAYLOAD_BINARY_FILE);
            }
            payloadOffset = getPayloadOffset(localFile, payloadEntry);
            payloadSize   = payloadEntry.getSize();
        }

        Log.d(TAG, "payload offset=" + payloadOffset + " size=" + payloadSize);
        Log.d(TAG, "properties: " + java.util.Arrays.toString(properties));

        String fileUrl = "file://" + localFile.getAbsolutePath();
        mUpdateEngine.bind(wrapCallback(callback));
        mUpdateEngine.applyPayload(fileUrl, payloadOffset, payloadSize, properties);
    }

    /** Cancels any in-progress update engine operation. */
    public void cancel() {
        Log.i(TAG, "Cancelling UpdateEngine operation");
        try {
            mUpdateEngine.cancel();
        } catch (Exception e) {
            Log.w(TAG, "Error cancelling UpdateEngine", e);
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Wraps the caller's UpdateEngineCallback to add human-readable status logging
     * and to trigger a normal reboot when STATUS_UPDATED_NEED_REBOOT is received.
     */
    private UpdateEngineCallback wrapCallback(UpdateEngineCallback delegate) {
        return new UpdateEngineCallback() {
            @Override
            public void onStatusUpdate(int status, float percent) {
                Log.i(TAG, "UpdateEngine status: " + statusName(status)
                        + " (" + (int)(percent * 100) + "%)");
                if (status == STATUS_UPDATED_NEED_REBOOT) {
                    Log.i(TAG, "Update applied — rebooting into new slot");
                    reboot();
                }
                if (delegate != null) {
                    delegate.onStatusUpdate(status, percent);
                }
            }

            @Override
            public void onPayloadApplicationComplete(int errorCode) {
                Log.i(TAG, "Payload application complete, errorCode=" + errorCode);
                if (delegate != null) {
                    delegate.onPayloadApplicationComplete(errorCode);
                }
            }
        };
    }

    private void reboot() {
        PowerManager pm = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
        if (pm != null) {
            // null reason = normal reboot; bootloader switches to newly-flashed A/B slot
            pm.reboot(null);
        } else {
            Log.e(TAG, "PowerManager unavailable — cannot reboot");
        }
    }

    /**
     * Reads lines from a ZIP entry into a String array of KEY=VALUE pairs.
     */
    private static String[] readProperties(ZipFile zipFile, ZipEntry entry) throws IOException {
        List<String> lines = new ArrayList<>();
        try (InputStream is = zipFile.getInputStream(entry)) {
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) > 0) {
                sb.append(new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8));
            }
            for (String line : sb.toString().split("\\r?\\n")) {
                line = line.trim();
                if (!line.isEmpty()) {
                    lines.add(line);
                }
            }
        }
        return lines.toArray(new String[0]);
    }

    /**
     * Determines the byte offset of payload.bin's data within the ZIP archive.
     *
     * A ZIP local file header is:
     *   4  bytes signature (0x04034b50)
     *   26 bytes fixed fields
     *   2  bytes filename length
     *   2  bytes extra field length
     *   N  bytes filename
     *   M  bytes extra field
     * followed immediately by the file data.
     */
    private static long getPayloadOffset(File zipFile, ZipEntry payloadEntry) throws IOException {
        // Use a random-access file to seek to the local header position
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(zipFile, "r")) {
            // ZipEntry.getCompressedSize() can be used; but we need the header offset.
            // Walk the zip from the start to find payload.bin's local header.
            // ZipFile does not expose the local header offset directly, so we enumerate.
            long offset = findLocalHeaderOffset(raf, PAYLOAD_BINARY_FILE);
            if (offset < 0) {
                throw new IOException("Cannot locate local header for " + PAYLOAD_BINARY_FILE);
            }
            // Read filename length (at offset+26) and extra field length (at offset+28)
            raf.seek(offset + 26);
            int fileNameLen  = readUInt16LE(raf);
            int extraLen     = readUInt16LE(raf);
            // Data starts after: 30-byte fixed header + filename + extra
            return offset + 30 + fileNameLen + extraLen;
        }
    }

    /**
     * Scans the ZIP sequentially to find the local file header for {@code entryName}.
     * Returns the byte offset of the local header signature, or -1 if not found.
     */
    private static long findLocalHeaderOffset(java.io.RandomAccessFile raf, String entryName)
            throws IOException {
        raf.seek(0);
        long fileLength = raf.length();
        long pos = 0;

        while (pos < fileLength - 4) {
            raf.seek(pos);
            int sig = readUInt16LE(raf) | (readUInt16LE(raf) << 16);
            if (sig == 0x04034b50) { // local file header signature
                // version needed (2), flags (2), compression (2), mod time (2), mod date (2),
                // crc32 (4), comp size (4), uncomp size (4) = 18 bytes; then filename length (2)
                raf.seek(pos + 26);
                int fnLen   = readUInt16LE(raf);
                int exLen   = readUInt16LE(raf);
                byte[] name = new byte[fnLen];
                raf.readFully(name);
                String foundName = new String(name, java.nio.charset.StandardCharsets.UTF_8);
                if (entryName.equals(foundName)) {
                    return pos;
                }
                // Advance past this entry: 30 + fnLen + exLen + compressed data
                // We need compressed size — it's at pos+18
                raf.seek(pos + 18);
                long compSize = readUInt32LE(raf);
                pos = pos + 30 + fnLen + exLen + compSize;
            } else {
                pos++;
            }
        }
        return -1;
    }

    private static int readUInt16LE(java.io.RandomAccessFile raf) throws IOException {
        int lo = raf.read();
        int hi = raf.read();
        return (hi << 8) | lo;
    }

    private static long readUInt32LE(java.io.RandomAccessFile raf) throws IOException {
        long b0 = raf.read();
        long b1 = raf.read();
        long b2 = raf.read();
        long b3 = raf.read();
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    /** Returns a human-readable name for an UpdateEngine status code. */
    private static String statusName(int status) {
        switch (status) {
            case STATUS_IDLE:                  return "STATUS_IDLE";
            case STATUS_CHECKING_FOR_UPDATE:   return "STATUS_CHECKING_FOR_UPDATE";
            case STATUS_UPDATE_AVAILABLE:      return "STATUS_UPDATE_AVAILABLE";
            case STATUS_DOWNLOADING:           return "STATUS_DOWNLOADING";
            case STATUS_VERIFYING:             return "STATUS_VERIFYING";
            case STATUS_FINALIZING:            return "STATUS_FINALIZING";
            case STATUS_UPDATED_NEED_REBOOT:   return "STATUS_UPDATED_NEED_REBOOT";
            case STATUS_REPORTING_ERROR_EVENT: return "STATUS_REPORTING_ERROR_EVENT";
            case STATUS_ATTEMPTING_ROLLBACK:   return "STATUS_ATTEMPTING_ROLLBACK";
            case STATUS_DISABLED:              return "STATUS_DISABLED";
            default:                           return "UNKNOWN(" + status + ")";
        }
    }
}
