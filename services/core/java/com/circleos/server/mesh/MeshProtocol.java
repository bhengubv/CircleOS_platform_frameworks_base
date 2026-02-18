/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.UUID;
import java.util.zip.CRC32;

/**
 * Circle Mesh wire protocol.
 *
 * HEADER (52 bytes, unencrypted):
 *   magic        4 bytes  0x434D5348 ("CMSH")
 *   version      1 byte   Protocol version (1)
 *   type         1 byte   Message type
 *   flags        1 byte   Bit flags (see FLAG_*)
 *   ttl          1 byte   Remaining hops
 *   sender_id    8 bytes  Sender device hash
 *   recipient_id 8 bytes  Recipient device hash (BROADCAST_ID for flood)
 *   message_id  16 bytes  UUID for deduplication
 *   timestamp    8 bytes  Unix timestamp (ms)
 *   length       4 bytes  Payload length
 *
 * PAYLOAD (variable, may be encrypted):
 *   [variable length]
 *
 * FOOTER (4 bytes):
 *   crc32        4 bytes  CRC32 of header + payload
 *
 * Total overhead: 56 bytes
 */
public class MeshProtocol {

    // ── Magic ────────────────────────────────────────────────────────────────

    public static final int  MAGIC   = 0x434D5348; // "CMSH"
    public static final byte VERSION = 1;

    // ── Message Types ────────────────────────────────────────────────────────

    // Discovery
    public static final byte TYPE_ANNOUNCE      = 0x01;
    public static final byte TYPE_DISCOVER      = 0x02;
    public static final byte TYPE_PEER_INFO     = 0x03;

    // OTA (chunk-based)
    public static final byte TYPE_CHUNK_MAP     = 0x04;
    public static final byte TYPE_CHUNK_DATA    = 0x05;
    public static final byte TYPE_CHUNK_ACK     = 0x06;

    // Messaging
    public static final byte TYPE_MSG_TEXT      = 0x10;
    public static final byte TYPE_MSG_MEDIA     = 0x11;
    public static final byte TYPE_MSG_ACK       = 0x12;
    public static final byte TYPE_MSG_READ      = 0x13;

    // SDPKT transactions
    public static final byte TYPE_TX_SYNC       = 0x20;
    public static final byte TYPE_TX_ACK        = 0x21;

    // Emergency broadcast
    public static final byte TYPE_BROADCAST     = 0x30;

    // Butler relay
    public static final byte TYPE_BUTLER_REQ    = 0x40;
    public static final byte TYPE_BUTLER_RES    = 0x41;

    // File sharing
    public static final byte TYPE_FILE_OFFER    = 0x50;
    public static final byte TYPE_FILE_ACCEPT   = 0x51;
    public static final byte TYPE_FILE_DATA     = 0x52;
    public static final byte TYPE_FILE_COMPLETE = 0x53;

    // Keep-alive
    public static final byte TYPE_PING          = (byte) 0xF0;
    public static final byte TYPE_PONG          = (byte) 0xF1;

    // ── Flags ─────────────────────────────────────────────────────────────────

    public static final byte FLAG_ENCRYPTED     = 0x01;
    public static final byte FLAG_COMPRESSED    = 0x02;
    public static final byte FLAG_URGENT        = 0x04;
    public static final byte FLAG_NO_RELAY      = 0x08;
    public static final byte FLAG_BROADCAST     = 0x10;
    public static final byte FLAG_ACK_REQUESTED = 0x20;
    public static final byte FLAG_FRAGMENTED    = 0x40;

    // ── Constants ─────────────────────────────────────────────────────────────

    public static final int  HEADER_SIZE   = 52;
    public static final int  FOOTER_SIZE   = 4;
    public static final int  OVERHEAD      = HEADER_SIZE + FOOTER_SIZE;
    public static final byte DEFAULT_TTL   = 5;
    public static final byte BROADCAST_TTL = 10;

    /** 8-byte broadcast recipient — all zeros. */
    public static final byte[] BROADCAST_ID = new byte[8];

    // ── Message record ────────────────────────────────────────────────────────

    public static class Message {
        public final int    magic;
        public final byte   version;
        public final byte   type;
        public final byte   flags;
        public final byte   ttl;
        public final byte[] senderId;      // 8 bytes
        public final byte[] recipientId;   // 8 bytes
        public final byte[] messageId;     // 16 bytes (UUID)
        public final long   timestamp;
        public final byte[] payload;

        public Message(int magic, byte version, byte type, byte flags, byte ttl,
                       byte[] senderId, byte[] recipientId, byte[] messageId,
                       long timestamp, byte[] payload) {
            this.magic       = magic;
            this.version     = version;
            this.type        = type;
            this.flags       = flags;
            this.ttl         = ttl;
            this.senderId    = senderId;
            this.recipientId = recipientId;
            this.messageId   = messageId;
            this.timestamp   = timestamp;
            this.payload     = payload;
        }

        public boolean hasFlag(byte flag) { return (flags & flag) != 0; }

        public boolean isBroadcast() { return Arrays.equals(recipientId, BROADCAST_ID); }

        /** Return UUID string form of messageId. */
        public String getMessageUuid() {
            ByteBuffer bb = ByteBuffer.wrap(messageId);
            long high = bb.getLong();
            long low  = bb.getLong();
            return new UUID(high, low).toString();
        }

        /** Return copy with ttl decremented by 1. */
        public Message decrementTtl() {
            return new Message(magic, version, type, flags, (byte)(ttl - 1),
                    senderId, recipientId, messageId, timestamp, payload);
        }

        /** Returns the sender device ID as a lowercase hex string. */
        public String getSenderHex() {
            if (senderId == null) return "";
            StringBuilder sb = new StringBuilder(senderId.length * 2);
            for (byte b : senderId) sb.append(String.format("%02x", b & 0xFF));
            return sb.toString();
        }
    }

    // ── Encode ────────────────────────────────────────────────────────────────

    public static byte[] encode(Message msg) {
        int payloadLen = msg.payload != null ? msg.payload.length : 0;
        int totalLen   = HEADER_SIZE + payloadLen + FOOTER_SIZE;
        ByteBuffer buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);

        buf.putInt(MAGIC);
        buf.put(msg.version);
        buf.put(msg.type);
        buf.put(msg.flags);
        buf.put(msg.ttl);
        buf.put(msg.senderId, 0, 8);
        buf.put(msg.recipientId, 0, 8);
        buf.put(msg.messageId, 0, 16);
        buf.putLong(msg.timestamp);
        buf.putInt(payloadLen);
        if (payloadLen > 0) buf.put(msg.payload);

        CRC32 crc = new CRC32();
        crc.update(buf.array(), 0, HEADER_SIZE + payloadLen);
        buf.putInt((int) crc.getValue());

        return buf.array();
    }

    // ── Decode ────────────────────────────────────────────────────────────────

    public static Message decode(byte[] data) {
        if (data == null || data.length < OVERHEAD)
            throw new IllegalArgumentException("Packet too short: "
                    + (data == null ? 0 : data.length));

        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);

        int  magic = buf.getInt();
        if (magic != MAGIC)
            throw new IllegalArgumentException("Bad magic: 0x" + Integer.toHexString(magic));

        byte version = buf.get();
        if (version != VERSION)
            throw new IllegalArgumentException("Unsupported version: " + version);

        byte type      = buf.get();
        byte flags     = buf.get();
        byte ttl       = buf.get();

        byte[] senderId    = new byte[8];  buf.get(senderId);
        byte[] recipientId = new byte[8];  buf.get(recipientId);
        byte[] messageId   = new byte[16]; buf.get(messageId);
        long   timestamp   = buf.getLong();
        int    payloadLen  = buf.getInt();

        if (data.length < HEADER_SIZE + payloadLen + FOOTER_SIZE)
            throw new IllegalArgumentException("Truncated packet");

        byte[] payload = new byte[payloadLen];
        if (payloadLen > 0) buf.get(payload);

        int storedCrc = buf.getInt();
        CRC32 crc = new CRC32();
        crc.update(data, 0, HEADER_SIZE + payloadLen);
        if ((int) crc.getValue() != storedCrc)
            throw new IllegalArgumentException("CRC mismatch");

        return new Message(magic, version, type, flags, ttl,
                senderId, recipientId, messageId, timestamp, payload);
    }

    // ── Builder helpers ───────────────────────────────────────────────────────

    private static byte[] newMessageId() {
        UUID uuid = UUID.randomUUID();
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return bb.array();
    }

    // ── Discovery ────────────────────────────────────────────────────────────

    public static Message buildAnnounce(byte[] senderId, byte[] payload) {
        return new Message(MAGIC, VERSION, TYPE_ANNOUNCE, (byte) 0, DEFAULT_TTL,
                senderId, BROADCAST_ID, newMessageId(), System.currentTimeMillis(), payload);
    }

    public static Message buildDiscover(byte[] senderId) {
        return new Message(MAGIC, VERSION, TYPE_DISCOVER, (byte) 0, DEFAULT_TTL,
                senderId, BROADCAST_ID, newMessageId(), System.currentTimeMillis(), null);
    }

    public static Message buildPeerInfo(byte[] senderId, byte[] recipientId, byte[] payload) {
        return new Message(MAGIC, VERSION, TYPE_PEER_INFO, (byte) 0, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), payload);
    }

    // ── OTA ──────────────────────────────────────────────────────────────────

    public static Message buildChunkMap(byte[] senderId, byte[] recipientId, byte[] bitmap) {
        return new Message(MAGIC, VERSION, TYPE_CHUNK_MAP, (byte) 0, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), bitmap);
    }

    public static Message buildChunkData(byte[] senderId, byte[] recipientId,
                                         int chunkIndex, byte[] data) {
        ByteBuffer b = ByteBuffer.allocate(4 + data.length).order(ByteOrder.BIG_ENDIAN);
        b.putInt(chunkIndex); b.put(data);
        return new Message(MAGIC, VERSION, TYPE_CHUNK_DATA, (byte) 0, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), b.array());
    }

    public static Message buildChunkAck(byte[] senderId, byte[] recipientId, int chunkIndex) {
        ByteBuffer b = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        b.putInt(chunkIndex);
        return new Message(MAGIC, VERSION, TYPE_CHUNK_ACK, (byte) 0, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), b.array());
    }

    // ── Messaging ────────────────────────────────────────────────────────────

    public static Message buildTextMessage(byte[] senderId, byte[] recipientId,
                                           byte[] encryptedPayload, boolean ackRequested) {
        byte flags = FLAG_ENCRYPTED;
        if (ackRequested) flags |= FLAG_ACK_REQUESTED;
        return new Message(MAGIC, VERSION, TYPE_MSG_TEXT, flags, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), encryptedPayload);
    }

    public static Message buildMsgAck(byte[] senderId, byte[] recipientId, byte[] ackMsgId) {
        return new Message(MAGIC, VERSION, TYPE_MSG_ACK, FLAG_ENCRYPTED, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), ackMsgId);
    }

    public static Message buildMediaMessage(byte[] senderId, byte[] recipientId,
                                            byte[] encryptedPayload) {
        return new Message(MAGIC, VERSION, TYPE_MSG_MEDIA,
                (byte)(FLAG_ENCRYPTED | FLAG_ACK_REQUESTED), DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), encryptedPayload);
    }

    // ── SDPKT ────────────────────────────────────────────────────────────────

    public static Message buildTxSync(byte[] senderId, byte[] recipientId, byte[] txBlob) {
        return new Message(MAGIC, VERSION, TYPE_TX_SYNC,
                (byte)(FLAG_ENCRYPTED | FLAG_ACK_REQUESTED), DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), txBlob);
    }

    public static Message buildTxAck(byte[] senderId, byte[] recipientId, byte[] txId) {
        return new Message(MAGIC, VERSION, TYPE_TX_ACK, FLAG_ENCRYPTED, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), txId);
    }

    // ── Broadcast ────────────────────────────────────────────────────────────

    public static Message buildBroadcast(byte[] senderId, byte[] signedPayload) {
        return new Message(MAGIC, VERSION, TYPE_BROADCAST,
                (byte)(FLAG_BROADCAST | FLAG_ACK_REQUESTED), BROADCAST_TTL,
                senderId, BROADCAST_ID, newMessageId(), System.currentTimeMillis(), signedPayload);
    }

    // ── Butler ───────────────────────────────────────────────────────────────

    public static Message buildButlerReq(byte[] senderId, byte[] recipientId,
                                         byte[] encryptedQuery) {
        return new Message(MAGIC, VERSION, TYPE_BUTLER_REQ,
                (byte)(FLAG_ENCRYPTED | FLAG_ACK_REQUESTED), DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), encryptedQuery);
    }

    public static Message buildButlerRes(byte[] senderId, byte[] recipientId,
                                         byte[] encryptedResponse) {
        return new Message(MAGIC, VERSION, TYPE_BUTLER_RES, FLAG_ENCRYPTED, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), encryptedResponse);
    }

    // ── File sharing ─────────────────────────────────────────────────────────

    public static Message buildFileOffer(byte[] senderId, byte[] recipientId, byte[] payload) {
        return new Message(MAGIC, VERSION, TYPE_FILE_OFFER, FLAG_ENCRYPTED, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), payload);
    }

    public static Message buildFileAccept(byte[] senderId, byte[] recipientId,
                                          byte[] transferId) {
        return new Message(MAGIC, VERSION, TYPE_FILE_ACCEPT, (byte) 0, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), transferId);
    }

    public static Message buildFileData(byte[] senderId, byte[] recipientId,
                                        int chunkIndex, byte[] data) {
        ByteBuffer b = ByteBuffer.allocate(4 + data.length).order(ByteOrder.BIG_ENDIAN);
        b.putInt(chunkIndex); b.put(data);
        return new Message(MAGIC, VERSION, TYPE_FILE_DATA, (byte) 0, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), b.array());
    }

    public static Message buildFileComplete(byte[] senderId, byte[] recipientId, byte[] sha256) {
        return new Message(MAGIC, VERSION, TYPE_FILE_COMPLETE, (byte) 0, DEFAULT_TTL,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), sha256);
    }

    // ── Keep-alive ───────────────────────────────────────────────────────────

    public static Message buildPing(byte[] senderId, byte[] recipientId) {
        return new Message(MAGIC, VERSION, TYPE_PING, (byte) 0, (byte) 1,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), null);
    }

    public static Message buildPong(byte[] senderId, byte[] recipientId,
                                    byte[] pingMessageId) {
        return new Message(MAGIC, VERSION, TYPE_PONG, (byte) 0, (byte) 1,
                senderId, recipientId, newMessageId(), System.currentTimeMillis(), pingMessageId);
    }

    // ── Type name helper ──────────────────────────────────────────────────────

    public static String typeName(byte type) {
        switch (type) {
            case TYPE_ANNOUNCE:      return "ANNOUNCE";
            case TYPE_DISCOVER:      return "DISCOVER";
            case TYPE_PEER_INFO:     return "PEER_INFO";
            case TYPE_CHUNK_MAP:     return "CHUNK_MAP";
            case TYPE_CHUNK_DATA:    return "CHUNK_DATA";
            case TYPE_CHUNK_ACK:     return "CHUNK_ACK";
            case TYPE_MSG_TEXT:      return "MSG_TEXT";
            case TYPE_MSG_MEDIA:     return "MSG_MEDIA";
            case TYPE_MSG_ACK:       return "MSG_ACK";
            case TYPE_MSG_READ:      return "MSG_READ";
            case TYPE_TX_SYNC:       return "TX_SYNC";
            case TYPE_TX_ACK:        return "TX_ACK";
            case TYPE_BROADCAST:     return "BROADCAST";
            case TYPE_BUTLER_REQ:    return "BUTLER_REQ";
            case TYPE_BUTLER_RES:    return "BUTLER_RES";
            case TYPE_FILE_OFFER:    return "FILE_OFFER";
            case TYPE_FILE_ACCEPT:   return "FILE_ACCEPT";
            case TYPE_FILE_DATA:     return "FILE_DATA";
            case TYPE_FILE_COMPLETE: return "FILE_COMPLETE";
            case TYPE_PING:          return "PING";
            case TYPE_PONG:          return "PONG";
            default: return "UNKNOWN(0x" + Integer.toHexString(type & 0xFF) + ")";
        }
    }

    // ── Convenience builder ────────────────────────────────────────────────────

    /**
     * Builds and encodes a mesh frame in one step.
     *
     * @param msgType     Message type constant (TYPE_*).
     * @param flags       Flag byte (FLAG_* constants, OR-combined).
     * @param ttl         Time-to-live hop count.
     * @param senderId    8-byte sender device ID.
     * @param recipientId 8-byte recipient device ID (all-zeros for broadcast).
     * @param messageId   16-byte unique message ID.
     * @param payload     Payload bytes (may be null or empty).
     * @return Fully encoded frame bytes, or null if encoding fails.
     */
    public static byte[] buildFrame(int msgType, byte flags, byte ttl,
            byte[] senderId, byte[] recipientId, byte[] messageId, byte[] payload) {
        try {
            Message msg = new Message(MAGIC, VERSION, (byte) msgType, flags, ttl,
                    senderId, recipientId, messageId,
                    System.currentTimeMillis(),
                    payload != null ? payload : new byte[0]);
            return encode(msg);
        } catch (Exception e) {
            return null;
        }
    }
}
