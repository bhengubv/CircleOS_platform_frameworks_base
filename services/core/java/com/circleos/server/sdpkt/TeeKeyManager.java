/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import za.co.circleos.sdpkt.WalletKey;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * TEE Key Manager — generates and stores the wallet keypair in the Android Keystore.
 *
 * Key properties:
 *   Algorithm:  EC (P-256 / secp256r1) — universally supported by Android Keystore.
 *               secp256k1 is available on some devices but not guaranteed. P-256
 *               provides equivalent security for this application.
 *   Purpose:    SIGN + VERIFY
 *   Digest:     SHA-256
 *   StrongBox:  Requested if available; falls back to TEE-backed if not.
 *   Auth:       Not required for the key itself — biometric/PIN confirmation is
 *               enforced at the transaction level by SdpktTitaniumService before
 *               calling sign() for large amounts.
 *
 * The private key NEVER leaves the secure element / TEE.
 * All signing operations happen inside the hardware boundary.
 */
public class TeeKeyManager {

    private static final String TAG       = "SdpktTeeKey";
    private static final String KEY_ALIAS = "circle_sdpkt_wallet_v1";
    private static final String PROVIDER  = "AndroidKeyStore";

    /**
     * Generate a new EC keypair in the TEE.
     * Returns the public key info, or null if generation failed.
     * Idempotent — returns existing key if already generated.
     */
    public WalletKey getOrCreateWalletKey() {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);

            if (!ks.containsAlias(KEY_ALIAS)) {
                generateKeyPair();
            }

            PublicKey pubKey = ks.getCertificate(KEY_ALIAS).getPublicKey();
            return buildWalletKey(pubKey);

        } catch (Exception e) {
            Log.e(TAG, "Failed to get/create wallet key", e);
            return null;
        }
    }

    /** True if the wallet keypair exists in the Keystore. */
    public boolean hasKey() {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            return ks.containsAlias(KEY_ALIAS);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Sign data using the wallet private key (inside TEE).
     * Returns base64-encoded ECDSA-SHA256 signature, or null on failure.
     */
    public String sign(byte[] data) {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            PrivateKey privateKey = (PrivateKey) ks.getKey(KEY_ALIAS, null);
            if (privateKey == null) {
                Log.e(TAG, "Private key not found in Keystore");
                return null;
            }

            java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
            sig.initSign(privateKey);
            sig.update(data);
            byte[] signature = sig.sign();
            return Base64.encodeToString(signature, Base64.NO_WRAP);

        } catch (Exception e) {
            Log.e(TAG, "Signing failed", e);
            return null;
        }
    }

    /**
     * Verify a signature against a public key.
     * @param data          The original signed data
     * @param signatureB64  Base64 ECDSA-SHA256 signature
     * @param pubKeyB64     Base64 X.509 SubjectPublicKeyInfo encoded public key
     */
    public boolean verify(byte[] data, String signatureB64, String pubKeyB64) {
        try {
            byte[] pubKeyBytes = Base64.decode(pubKeyB64, Base64.NO_WRAP);
            java.security.spec.X509EncodedKeySpec spec =
                    new java.security.spec.X509EncodedKeySpec(pubKeyBytes);
            PublicKey pubKey = KeyFactory.getInstance("EC").generatePublic(spec);

            java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pubKey);
            sig.update(data);
            return sig.verify(Base64.decode(signatureB64, Base64.NO_WRAP));

        } catch (Exception e) {
            Log.w(TAG, "Signature verification failed", e);
            return false;
        }
    }

    /** Return the encoded public key of this wallet (base64 X.509). */
    public String getEncodedPublicKey() {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            if (!ks.containsAlias(KEY_ALIAS)) return null;
            PublicKey pubKey = ks.getCertificate(KEY_ALIAS).getPublicKey();
            return Base64.encodeToString(pubKey.getEncoded(), Base64.NO_WRAP);
        } catch (Exception e) {
            Log.e(TAG, "Cannot retrieve public key", e);
            return null;
        }
    }

    /* ── Private ─────────────────────────────────────── */

    private void generateKeyPair() throws Exception {
        // Try StrongBox first; fall back to TEE-backed
        boolean generated = tryGenerateKeyPair(true);
        if (!generated) {
            Log.w(TAG, "StrongBox unavailable — falling back to TEE");
            tryGenerateKeyPair(false);
        }
    }

    private boolean tryGenerateKeyPair(boolean strongBox) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, PROVIDER);

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setIsStrongBoxBacked(strongBox);

            kpg.initialize(builder.build());
            KeyPair kp = kpg.generateKeyPair();
            Log.i(TAG, "Wallet keypair generated ("
                    + (strongBox ? "StrongBox" : "TEE") + ")");
            return true;

        } catch (Exception e) {
            if (strongBox) {
                Log.d(TAG, "StrongBox key gen failed: " + e.getMessage());
            } else {
                Log.e(TAG, "TEE key gen failed", e);
            }
            return false;
        }
    }

    private WalletKey buildWalletKey(PublicKey pubKey) throws Exception {
        byte[] encoded = pubKey.getEncoded();
        String encodedB64 = Base64.encodeToString(encoded, Base64.NO_WRAP);
        String deviceId = sha256Hex(encoded);

        WalletKey wk = new WalletKey();
        wk.encodedPublicKey = encodedB64;
        wk.deviceId         = deviceId;
        wk.walletAddress    = deviceId;  // full 64-char hex
        wk.createdAtMs      = System.currentTimeMillis();
        wk.keystoreType     = detectKeystoreType();
        return wk;
    }

    private int detectKeystoreType() {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            PrivateKey pk = (PrivateKey) ks.getKey(KEY_ALIAS, null);
            if (pk == null) return WalletKey.KEYSTORE_SOFTWARE;
            KeyFactory kf = KeyFactory.getInstance(pk.getAlgorithm(), PROVIDER);
            KeyInfo info = kf.getKeySpec(pk, KeyInfo.class);
            if (info.isInsideSecureHardware()) {
                // Android 12+ can distinguish StrongBox vs TEE via getSecurityLevel()
                return WalletKey.KEYSTORE_TEE; // conservative — StrongBox detection in Phase 2
            }
            return WalletKey.KEYSTORE_SOFTWARE;
        } catch (Exception e) {
            return WalletKey.KEYSTORE_SOFTWARE;
        }
    }

    static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);
        StringBuilder sb = new StringBuilder(64);
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
