/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

package com.circleos.server.mesh;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Link-layer metadata privacy for the mesh — closes the BLE-fingerprint and
 * cleartext-envelope gaps.
 *
 * A 32-byte network pre-shared key (the Thread/Zigbee "network key" model) is
 * baked into the build. From it, per-epoch (daily) values are derived:
 *
 *   - {@link #serviceUuid}: the BLE service UUID rotates daily and is NOT a fixed
 *     constant, so a passive scanner without the network key can't even tell
 *     "this is a Circle device" — the fingerprint is gone for outside observers.
 *   - {@link #linkEncrypt}: the whole frame (already E2E inside) is wrapped in a
 *     second, link-layer ChaCha20-Poly1305 layer keyed by the network key, so the
 *     envelope — version, padded length, everything — is opaque on the air.
 *
 * Content stays E2E between endpoints (the network key never sees plaintext); this
 * layer defeats *non-Circle* observers doing fingerprinting / bulk metadata
 * collection. Honest limit: someone who reverse-engineers the firmware can extract
 * the network key and re-fingerprint; the bar is "passive bulk surveillance", not
 * "a determined attacker with your binary". Pure JCA — unit-testable off-device.
 */
final class MeshLinkPrivacy {

    /** Network pre-shared key. Rotate the build to rotate this. */
    private static final byte[] NETWORK_PSK = {
        (byte) 0xC1, (byte) 0x3C, (byte) 0x4E, (byte) 0xA7, (byte) 0x91, (byte) 0x05, (byte) 0xBE, (byte) 0x2D,
        (byte) 0x7F, (byte) 0x88, (byte) 0x44, (byte) 0x19, (byte) 0xD0, (byte) 0x6B, (byte) 0xF2, (byte) 0x3A,
        (byte) 0x5C, (byte) 0xA0, (byte) 0xE1, (byte) 0x9B, (byte) 0x2F, (byte) 0x70, (byte) 0x8D, (byte) 0xC4,
        (byte) 0x11, (byte) 0x66, (byte) 0x99, (byte) 0xAB, (byte) 0xEE, (byte) 0x33, (byte) 0x55, (byte) 0x77,
    };

    private static final long EPOCH_MS = 24L * 60 * 60 * 1000; // daily rotation
    private static final byte[] INFO_UUID = "circle-mesh-uuid-v2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO_LINK = "circle-mesh-link-v2".getBytes(StandardCharsets.UTF_8);
    private static final int NONCE_LEN = 12;
    private static final int TAG_LEN = 16;

    private MeshLinkPrivacy() {}

    /** Current rotation epoch (caller can also pass an explicit epoch in tests). */
    static long currentEpoch(long nowMs) {
        return nowMs / EPOCH_MS;
    }

    /** The BLE service UUID for an epoch — rotates daily, unguessable without the network key. */
    static UUID serviceUuid(long epoch) {
        byte[] k = hkdf(NETWORK_PSK, le8(epoch), INFO_UUID, 16);
        return new UUID(beLong(k, 0), beLong(k, 8));
    }

    /** Wrap a frame in the link layer: returns [nonce][ciphertext+tag], opaque on the air. */
    static byte[] linkEncrypt(long epoch, byte[] frame) {
        try {
            byte[] key = linkKey(epoch);
            byte[] nonce = new byte[NONCE_LEN];
            new SecureRandom().nextBytes(nonce);
            Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
            byte[] ct = c.doFinal(frame);
            byte[] out = new byte[NONCE_LEN + ct.length];
            System.arraycopy(nonce, 0, out, 0, NONCE_LEN);
            System.arraycopy(ct, 0, out, NONCE_LEN, ct.length);
            Arrays.fill(key, (byte) 0);
            return out;
        } catch (Throwable t) {
            return null;
        }
    }

    /** Unwrap a link blob -> the frame, trying this epoch and the previous one (clock skew). */
    static byte[] linkDecrypt(long epoch, byte[] blob) {
        byte[] r = tryDecrypt(epoch, blob);
        if (r != null) return r;
        return tryDecrypt(epoch - 1, blob);
    }

    private static byte[] tryDecrypt(long epoch, byte[] blob) {
        try {
            if (blob == null || blob.length < NONCE_LEN + TAG_LEN) return null;
            byte[] key = linkKey(epoch);
            byte[] nonce = Arrays.copyOfRange(blob, 0, NONCE_LEN);
            byte[] ct = Arrays.copyOfRange(blob, NONCE_LEN, blob.length);
            Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
            byte[] pt = c.doFinal(ct);
            Arrays.fill(key, (byte) 0);
            return pt;
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] linkKey(long epoch) {
        return hkdf(NETWORK_PSK, le8(epoch), INFO_LINK, 32);
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] out = new byte[len];
            byte[] t = new byte[0];
            int pos = 0, counter = 1;
            while (pos < len) {
                mac.reset();
                mac.update(t);
                mac.update(info);
                mac.update((byte) counter);
                t = mac.doFinal();
                int n = Math.min(t.length, len - pos);
                System.arraycopy(t, 0, out, pos, n);
                pos += n;
                counter++;
            }
            return out;
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] le8(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) b[i] = (byte) ((v >> (8 * i)) & 0xff);
        return b;
    }

    private static long beLong(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[off + i] & 0xffL);
        return v;
    }
}
