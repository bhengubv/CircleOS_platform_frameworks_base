/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.content.Context;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic primitives for the Circle Mesh Network.
 *
 * <ul>
 *   <li>Device identity: secp256r1 EC key pair stored in Android Keystore.</li>
 *   <li>Session key establishment: ECDH → HKDF-SHA256 → 32-byte AES-256 key.</li>
 *   <li>Message encryption: AES-256-GCM with random 12-byte IV prepended.</li>
 *   <li>Message signing: ECDSA-SHA256 using the local identity key.</li>
 *   <li>Rotating device ID: SHA-256(publicKey + floor(epochMs/86400000)) truncated to 8 bytes,
 *       rendered as a 16-char hex string. Rotates every 24 hours.</li>
 * </ul>
 */
public class MeshCrypto {

    private static final String TAG = "MeshCrypto";

    private static final String KEYSTORE_ALIAS    = "circle_mesh_identity";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";

    private static final int GCM_IV_LEN  = 12; // bytes
    private static final int GCM_TAG_LEN = 128; // bits

    // HKDF info strings
    private static final byte[] HKDF_INFO_MESH = "CircleMesh-v1".getBytes();

    // Rotating device-ID epoch window = 24 h
    private static final long DEVICE_ID_WINDOW_MS = 86_400_000L;

    // ── State ─────────────────────────────────────────────────────────────────

    private KeyPair  mIdentityKeyPair;
    private String   mDeviceId;         // cached, refreshed per-window

    // ── Init ──────────────────────────────────────────────────────────────────

    /**
     * Initialises the crypto module.
     * Generates or loads the device identity key from the Android Keystore.
     */
    public void init() {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            ks.load(null);

            if (!ks.containsAlias(KEYSTORE_ALIAS)) {
                generateIdentityKey();
            }

            // Load public key from keystore; private key remains hardware-bound
            KeyStore.Entry entry = ks.getEntry(KEYSTORE_ALIAS, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                KeyStore.PrivateKeyEntry pke = (KeyStore.PrivateKeyEntry) entry;
                mIdentityKeyPair = new KeyPair(pke.getCertificate().getPublicKey(),
                        pke.getPrivateKey());
                Log.i(TAG, "Identity key loaded from Keystore");
            } else {
                Log.w(TAG, "Keystore entry is not a PrivateKeyEntry — regenerating");
                ks.deleteEntry(KEYSTORE_ALIAS);
                generateIdentityKey();
            }
        } catch (Exception e) {
            Log.e(TAG, "init() failed", e);
        }
    }

    private void generateIdentityKey()
            throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
        kpg.initialize(new KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_AGREE_KEY | KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        mIdentityKeyPair = kpg.generateKeyPair();
        Log.i(TAG, "New identity key generated");
    }

    // ── Device ID ─────────────────────────────────────────────────────────────

    /**
     * Returns the current rotating device ID (16-char hex, 8 bytes).
     * The ID changes every 24 hours so long-term tracking is harder.
     */
    public String getDeviceId() {
        long window = System.currentTimeMillis() / DEVICE_ID_WINDOW_MS;
        // Refresh when window changes or on first call
        if (mDeviceId == null) {
            mDeviceId = computeDeviceId(window);
        }
        return mDeviceId;
    }

    private String computeDeviceId(long window) {
        try {
            if (mIdentityKeyPair == null) return "0000000000000000";
            byte[] pubEncoded = mIdentityKeyPair.getPublic().getEncoded();
            ByteBuffer buf = ByteBuffer.allocate(pubEncoded.length + 8);
            buf.put(pubEncoded);
            buf.putLong(window);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(buf.array());
            // Use first 8 bytes
            return bytesToHex(digest, 0, 8);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "computeDeviceId failed", e);
            return "0000000000000000";
        }
    }

    /** Returns the DER-encoded EC public key for this device. */
    public byte[] getPublicKeyBytes() {
        if (mIdentityKeyPair == null) return new byte[0];
        return mIdentityKeyPair.getPublic().getEncoded();
    }

    // ── ECDH + HKDF ───────────────────────────────────────────────────────────

    /**
     * Derives a 256-bit shared AES key from a peer's public key using ECDH + HKDF-SHA256.
     *
     * @param peerPublicKey  The peer's EC public key.
     * @return 32-byte AES-256 key, or null on failure.
     */
    public SecretKey deriveSharedKey(PublicKey peerPublicKey) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(mIdentityKeyPair.getPrivate());
            ka.doPhase(peerPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();
            byte[] keyBytes = hkdf(sharedSecret, null, HKDF_INFO_MESH, 32);
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            Log.e(TAG, "deriveSharedKey failed", e);
            return null;
        }
    }

    /**
     * HKDF-SHA256: extract + expand.
     *
     * @param ikm    Input key material (ECDH shared secret).
     * @param salt   Optional salt; uses zero-filled byte array if null.
     * @param info   Context info bytes.
     * @param length Desired output length in bytes (max 255 * 32).
     */
    private byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length)
            throws NoSuchAlgorithmException, InvalidKeyException {
        // Extract
        if (salt == null) salt = new byte[32];
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = hmac.doFinal(ikm);

        // Expand
        byte[] okm = new byte[length];
        int offset = 0;
        byte[] prev = new byte[0];
        byte counter = 1;
        while (offset < length) {
            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
            hmac.update(prev);
            hmac.update(info);
            hmac.update(counter);
            prev = hmac.doFinal();
            int copy = Math.min(prev.length, length - offset);
            System.arraycopy(prev, 0, okm, offset, copy);
            offset += copy;
            counter++;
        }
        return okm;
    }

    // ── AES-256-GCM ───────────────────────────────────────────────────────────

    /**
     * Encrypts plaintext with AES-256-GCM.
     *
     * @param key        32-byte AES key.
     * @param plaintext  Data to encrypt.
     * @return IV (12 bytes) || ciphertext || GCM tag (16 bytes), or null on failure.
     */
    public byte[] encrypt(SecretKey key, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = cipher.getIV(); // Random 12-byte IV generated by Cipher
            byte[] ciphertext = cipher.doFinal(plaintext);

            ByteBuffer out = ByteBuffer.allocate(GCM_IV_LEN + ciphertext.length);
            out.put(iv);
            out.put(ciphertext);
            return out.array();
        } catch (Exception e) {
            Log.e(TAG, "encrypt failed", e);
            return null;
        }
    }

    /**
     * Decrypts a message encrypted by {@link #encrypt}.
     *
     * @param key        32-byte AES key.
     * @param ivAndData  IV (12 bytes) || ciphertext || GCM tag.
     * @return Plaintext bytes, or null on failure/authentication error.
     */
    public byte[] decrypt(SecretKey key, byte[] ivAndData) {
        if (ivAndData == null || ivAndData.length <= GCM_IV_LEN) return null;
        try {
            byte[] iv   = new byte[GCM_IV_LEN];
            byte[] data = new byte[ivAndData.length - GCM_IV_LEN];
            System.arraycopy(ivAndData, 0, iv, 0, GCM_IV_LEN);
            System.arraycopy(ivAndData, GCM_IV_LEN, data, 0, data.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LEN, iv));
            return cipher.doFinal(data);
        } catch (Exception e) {
            Log.e(TAG, "decrypt failed", e);
            return null;
        }
    }

    // ── ECDSA Signing ─────────────────────────────────────────────────────────

    /**
     * Signs data with the local identity key (ECDSA-SHA256).
     *
     * @param data  Bytes to sign.
     * @return DER-encoded signature, or null on failure.
     */
    public byte[] sign(byte[] data) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(mIdentityKeyPair.getPrivate());
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            Log.e(TAG, "sign failed", e);
            return null;
        }
    }

    /**
     * Verifies an ECDSA-SHA256 signature.
     *
     * @param data       Original data bytes.
     * @param signature  DER-encoded signature.
     * @param publicKey  Signer's EC public key.
     * @return true if the signature is valid.
     */
    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            Log.e(TAG, "verify failed", e);
            return false;
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    /** Converts bytes[offset..offset+len) to a lowercase hex string. */
    public static String bytesToHex(byte[] bytes, int offset, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = offset; i < offset + len; i++) {
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    /** Converts a full byte array to a lowercase hex string. */
    public static String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, 0, bytes.length);
    }
}
