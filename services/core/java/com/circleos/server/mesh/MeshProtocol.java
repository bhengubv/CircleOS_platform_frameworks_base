/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.util.Slog;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

/**
 * CircleOS Mesh OTA wire protocol encoder/decoder.
 *
 * Frame layout:
 *   4 bytes: Magic (0x434D5348 = "CMSH")
 *   1 byte:  Version (0x01)
 *   1 byte:  Message type
 *   4 bytes: Payload length (big-endian, unsigned)
 *   N bytes: Payload
 *   4 bytes: CRC32 of (magic + version + type + length + payload)
 *
 * Message types:
 *   0x01 ANNOUNCE      — "I have version X, chunks bitmap"
 *   0x02 DISCOVER      — "Who has chunks for version X?"
 *   0x03 CHUNK_MAP     — Response to DISCOVER: bitmap of available chunks
 *   0x04 CHUNK_REQUEST — "Send me chunk index N"
 *   0x05 CHUNK_DATA    — Chunk payload
 *   0x06 CHUNK_ACK     — "Got chunk N, hash OK/FAIL"
 */
public final class MeshProtocol {

    private static final String TAG = "MeshProtocol";

    // ---- Constants ----

    /** Wire magic: "CMSH" */
    public static final int MAGIC   = 0x434D5348;
    /** Protocol version. */
    public static final byte VERSION = 0x01;

    /** Message type: announce presence and available chunks. */
    public static final int MSG_ANNOUNCE      = 0x01;
    /** Message type: discover peers with chunks for a version. */
    public static final int MSG_DISCOVER      = 0x02;
    /** Message type: respond to DISCOVER with available chunk bitmap. */
    public static final int MSG_CHUNK_MAP     = 0x03;
    /** Message type: request a specific chunk by index. */
    public static final int MSG_CHUNK_REQUEST = 0x04;
    /** Message type: carry chunk payload data. */
    public static final int MSG_CHUNK_DATA    = 0x05;
    /** Message type: acknowledge receipt and hash verification of a chunk. */
    public static final int MSG_CHUNK_ACK     = 0x06;

    // Fixed header size: magic(4) + version(1) + type(1) + length(4) = 10 bytes
    private static final int HEADER_SIZE = 10;
    // CRC trailer size
    private static final int CRC_SIZE = 4;

    // Maximum sane payload: 2 MB (protects against runaway length fields)
    private static final int MAX_PAYLOAD = 2 * 1024 * 1024;

    // Private constructor — static utility class
    private MeshProtocol() {}

    // -------------------------------------------------------------------------
    // Inner classes
    // -------------------------------------------------------------------------

    /**
     * A decoded mesh protocol message.
     */
    public static final class Message {
        /** One of the MSG_* constants. */
        public final int type;
        /** Raw payload bytes. May be zero-length but never null. */
        public final byte[] payload;

        Message(int type, byte[] payload) {
            this.type    = type;
            this.payload = payload != null ? payload : new byte[0];
        }
    }

    // -------------------------------------------------------------------------
    // Core encode / decode
    // -------------------------------------------------------------------------

    /**
     * Builds a complete framed message.
     *
     * @param type    One of the MSG_* type constants.
     * @param payload Message payload bytes (may be null or empty).
     * @return Fully framed byte array ready to write to a socket.
     */
    public static byte[] encode(int type, byte[] payload) {
        if (payload == null) payload = new byte[0];

        int payloadLen = payload.length;
        // Header (10) + payload + CRC (4)
        byte[] frame = new byte[HEADER_SIZE + payloadLen + CRC_SIZE];
        ByteBuffer buf = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN);

        // Write header
        buf.putInt(MAGIC);
        buf.put(VERSION);
        buf.put((byte) type);
        buf.putInt(payloadLen);
        // Write payload
        buf.put(payload);

        // Compute and append CRC32 over all bytes before the CRC field
        CRC32 crc = new CRC32();
        crc.update(frame, 0, HEADER_SIZE + payloadLen);
        buf.putInt((int) crc.getValue());

        return frame;
    }

    /**
     * Reads exactly one message from the given stream.
     *
     * Validates the magic, version, and trailing CRC32. Blocks until a full
     * message is available or an error occurs.
     *
     * @param in Socket InputStream positioned at the start of a frame.
     * @return The decoded {@link Message}, never null.
     * @throws IOException If the stream ends, the magic/version is wrong, the
     *                     CRC fails, or the payload length is unreasonable.
     */
    public static Message decode(InputStream in) throws IOException {
        // Read fixed header
        byte[] header = readFully(in, HEADER_SIZE);

        ByteBuffer hbuf = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN);
        int magic = hbuf.getInt();
        if (magic != MAGIC) {
            throw new IOException(String.format(
                    "Bad magic: expected 0x%08X got 0x%08X", MAGIC, magic));
        }

        byte version = hbuf.get();
        if (version != VERSION) {
            throw new IOException("Unsupported protocol version: " + (version & 0xFF));
        }

        int type       = hbuf.get() & 0xFF;
        int payloadLen = hbuf.getInt();

        if (payloadLen < 0 || payloadLen > MAX_PAYLOAD) {
            throw new IOException("Unreasonable payload length: " + payloadLen);
        }

        // Read payload
        byte[] payload = readFully(in, payloadLen);

        // Read and verify CRC
        byte[] crcBytes = readFully(in, CRC_SIZE);
        int receivedCrc = ByteBuffer.wrap(crcBytes).order(ByteOrder.BIG_ENDIAN).getInt();

        CRC32 crc = new CRC32();
        crc.update(header);
        crc.update(payload);
        int computedCrc = (int) crc.getValue();

        if (receivedCrc != computedCrc) {
            throw new IOException(String.format(
                    "CRC32 mismatch: expected 0x%08X got 0x%08X", computedCrc, receivedCrc));
        }

        return new Message(type, payload);
    }

    // -------------------------------------------------------------------------
    // Message builders
    // -------------------------------------------------------------------------

    /**
     * Builds an ANNOUNCE message.
     *
     * Payload layout:
     *   2 bytes: version string length (big-endian)
     *   N bytes: version string (UTF-8)
     *   4 bytes: bitmap length (big-endian)
     *   M bytes: chunk bitmap (one byte per chunk, 1 = have, 0 = missing)
     *
     * @param version     OTA version string (e.g. "1.2.3-alpha").
     * @param chunkBitmap Bitmap array where byte[i] != 0 means chunk i is held.
     */
    public static byte[] buildAnnounce(String version, byte[] chunkBitmap) {
        return encode(MSG_ANNOUNCE, buildVersionBitmapPayload(version, chunkBitmap));
    }

    /**
     * Builds a DISCOVER message.
     *
     * Payload layout:
     *   2 bytes: version string length (big-endian)
     *   N bytes: version string (UTF-8)
     *
     * @param version OTA version string being queried.
     */
    public static byte[] buildDiscover(String version) {
        return encode(MSG_DISCOVER, buildVersionPayload(version));
    }

    /**
     * Builds a CHUNK_MAP response message.
     *
     * Payload layout: same as ANNOUNCE.
     *
     * @param version     OTA version string.
     * @param bitmap      Bitmap of locally available chunks.
     */
    public static byte[] buildChunkMap(String version, byte[] bitmap) {
        return encode(MSG_CHUNK_MAP, buildVersionBitmapPayload(version, bitmap));
    }

    /**
     * Builds a CHUNK_REQUEST message.
     *
     * Payload layout:
     *   4 bytes: chunk index (big-endian, unsigned)
     *
     * @param chunkIndex Zero-based chunk index being requested.
     */
    public static byte[] buildChunkRequest(int chunkIndex) {
        ByteBuffer buf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(chunkIndex);
        return encode(MSG_CHUNK_REQUEST, buf.array());
    }

    /**
     * Builds a CHUNK_DATA message.
     *
     * Payload layout:
     *   4 bytes: chunk index (big-endian)
     *   4 bytes: data length (big-endian)
     *   N bytes: raw chunk data
     *
     * @param chunkIndex Zero-based chunk index.
     * @param data       Raw chunk bytes.
     */
    public static byte[] buildChunkData(int chunkIndex, byte[] data) {
        if (data == null) data = new byte[0];
        ByteBuffer buf = ByteBuffer.allocate(4 + 4 + data.length).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(chunkIndex);
        buf.putInt(data.length);
        buf.put(data);
        return encode(MSG_CHUNK_DATA, buf.array());
    }

    /**
     * Builds a CHUNK_ACK message.
     *
     * Payload layout:
     *   4 bytes: chunk index (big-endian)
     *   1 byte:  status — 0x01 = OK, 0x00 = hash FAIL
     *
     * @param chunkIndex Zero-based chunk index being acknowledged.
     * @param ok         True if SHA-256 verification passed.
     */
    public static byte[] buildChunkAck(int chunkIndex, boolean ok) {
        ByteBuffer buf = ByteBuffer.allocate(5).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(chunkIndex);
        buf.put(ok ? (byte) 0x01 : (byte) 0x00);
        return encode(MSG_CHUNK_ACK, buf.array());
    }

    // -------------------------------------------------------------------------
    // Payload helpers
    // -------------------------------------------------------------------------

    /**
     * Parses the chunk index from a CHUNK_REQUEST payload.
     *
     * @param payload Raw payload bytes from a decoded Message.
     * @return The chunk index, or -1 if the payload is malformed.
     */
    public static int parseChunkIndex(byte[] payload) {
        if (payload == null || payload.length < 4) return -1;
        return ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN).getInt();
    }

    /**
     * Parses the version string from a DISCOVER or CHUNK_MAP payload.
     *
     * @param payload Raw payload bytes.
     * @return The version string, or null if malformed.
     */
    public static String parseVersion(byte[] payload) {
        if (payload == null || payload.length < 2) return null;
        try {
            ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
            int vlen = buf.getShort() & 0xFFFF;
            if (vlen < 0 || vlen > payload.length - 2) return null;
            byte[] vbytes = new byte[vlen];
            buf.get(vbytes);
            return new String(vbytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Slog.w(TAG, "parseVersion failed", e);
            return null;
        }
    }

    /**
     * Parses the bitmap from an ANNOUNCE or CHUNK_MAP payload.
     *
     * @param payload Raw payload bytes.
     * @return The chunk bitmap, or null if malformed.
     */
    public static byte[] parseBitmap(byte[] payload) {
        if (payload == null || payload.length < 2) return null;
        try {
            ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
            int vlen = buf.getShort() & 0xFFFF;
            if (vlen < 0 || buf.remaining() < vlen + 4) return null;
            buf.position(buf.position() + vlen); // skip version string
            int bitmapLen = buf.getInt();
            if (bitmapLen < 0 || buf.remaining() < bitmapLen) return null;
            byte[] bitmap = new byte[bitmapLen];
            buf.get(bitmap);
            return bitmap;
        } catch (Exception e) {
            Slog.w(TAG, "parseBitmap failed", e);
            return null;
        }
    }

    /**
     * Parses the chunk index and data from a CHUNK_DATA payload.
     *
     * @param payload Raw payload bytes.
     * @return Two-element array: [0] = int chunk index boxed as Integer (may be null on error),
     *         [1] = byte[] data. Returns null if payload is malformed.
     */
    public static Object[] parseChunkData(byte[] payload) {
        if (payload == null || payload.length < 8) return null;
        try {
            ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
            int index   = buf.getInt();
            int dataLen = buf.getInt();
            if (dataLen < 0 || buf.remaining() < dataLen) return null;
            byte[] data = new byte[dataLen];
            buf.get(data);
            return new Object[]{index, data};
        } catch (Exception e) {
            Slog.w(TAG, "parseChunkData failed", e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Builds a payload containing a version string followed by a chunk bitmap. */
    private static byte[] buildVersionBitmapPayload(String version, byte[] bitmap) {
        if (version == null) version = "";
        if (bitmap  == null) bitmap  = new byte[0];
        byte[] vbytes = version.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(2 + vbytes.length + 4 + bitmap.length)
                .order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) vbytes.length);
        buf.put(vbytes);
        buf.putInt(bitmap.length);
        buf.put(bitmap);
        return buf.array();
    }

    /** Builds a payload containing only a version string. */
    private static byte[] buildVersionPayload(String version) {
        if (version == null) version = "";
        byte[] vbytes = version.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(2 + vbytes.length).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) vbytes.length);
        buf.put(vbytes);
        return buf.array();
    }

    /**
     * Reads exactly {@code count} bytes from {@code in}, blocking until all
     * bytes are available or the stream ends.
     *
     * @throws IOException If fewer than {@code count} bytes are available
     *                     before EOF.
     */
    private static byte[] readFully(InputStream in, int count) throws IOException {
        if (count == 0) return new byte[0];
        byte[] buf = new byte[count];
        int offset = 0;
        while (offset < count) {
            int read = in.read(buf, offset, count - offset);
            if (read < 0) {
                throw new IOException("Stream ended after " + offset + " of " + count + " bytes");
            }
            offset += read;
        }
        return buf;
    }
}
