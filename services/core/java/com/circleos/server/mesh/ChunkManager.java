/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.mesh;

import android.content.Context;
import android.util.Slog;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages on-disk storage and tracking of OTA chunks for a single version.
 *
 * Storage layout under /data/system/circleos_mesh/{version}/:
 *   manifest.json   — chunk manifest (index, offset, size, sha256 per chunk)
 *   chunks/
 *       000.chunk   — 1 MB raw chunk data
 *       001.chunk
 *       ...
 *   bitmap          — one byte per chunk: 0x00 = missing, 0x01 = have
 *   assembled.zip   — written when all chunks present and total hash verified
 *
 * Thread-safety: individual chunk file writes are serialized by chunk index.
 * The bitmap file is written under {@code this} lock. Callers should not rely
 * on atomic all-or-nothing visibility across multiple chunks.
 */
public final class ChunkManager {

    private static final String TAG = "ChunkManager";

    private static final String BASE_DIR      = "/data/system/circleos_mesh";
    private static final String MANIFEST_FILE = "manifest.json";
    private static final String CHUNKS_DIR    = "chunks";
    private static final String BITMAP_FILE   = "bitmap";
    private static final String ASSEMBLED_FILE = "assembled.zip";

    // -------------------------------------------------------------------------
    // Inner classes
    // -------------------------------------------------------------------------

    /**
     * Metadata for a single OTA chunk as parsed from the server manifest.
     */
    public static final class ChunkInfo {
        /** Zero-based position of this chunk in the final assembled file. */
        public final int index;
        /** Byte offset of this chunk in the assembled file. */
        public final long offset;
        /** Size of this chunk in bytes. */
        public final int size;
        /** Expected SHA-256 hex digest of the raw chunk data. */
        public final String sha256;

        ChunkInfo(int index, long offset, int size, String sha256) {
            this.index  = index;
            this.offset = offset;
            this.size   = size;
            this.sha256 = sha256;
        }
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private final String      mVersion;
    private final File        mVersionDir;
    private final File        mChunksDir;
    private final File        mBitmapFile;
    private final File        mAssembledFile;
    private final ChunkInfo[] mChunks;       // indexed by chunk index
    private final byte[]      mBitmap;       // in-memory mirror of bitmap file
    private final String      mTotalSha256;  // whole-file SHA-256 from manifest

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * Creates (or resumes) chunk management for the given OTA version.
     *
     * @param ctx          System context (used for file-system paths only).
     * @param version      OTA version string (e.g. "1.2.3-alpha").
     * @param manifestJson JSON manifest from the update server. Expected format:
     *                     <pre>{
     *                       "version": "1.2.3-alpha",
     *                       "total_sha256": "...",
     *                       "chunks": [
     *                         { "index": 0, "offset": 0, "size": 1048576, "sha256": "..." },
     *                         ...
     *                       ]
     *                     }</pre>
     * @throws IllegalArgumentException If the manifest cannot be parsed.
     */
    public ChunkManager(Context ctx, String version, String manifestJson) {
        mVersion = version;

        mVersionDir    = new File(BASE_DIR, sanitizeVersion(version));
        mChunksDir     = new File(mVersionDir, CHUNKS_DIR);
        mBitmapFile    = new File(mVersionDir, BITMAP_FILE);
        mAssembledFile = new File(mVersionDir, ASSEMBLED_FILE);

        // Parse manifest
        ChunkInfo[] chunks;
        String totalSha256;
        try {
            JSONObject root = new JSONObject(manifestJson);
            totalSha256 = root.optString("total_sha256", "");
            JSONArray arr = root.getJSONArray("chunks");
            chunks = new ChunkInfo[arr.length()];
            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                int idx    = obj.getInt("index");
                long offset = obj.getLong("offset");
                int size   = obj.getInt("size");
                String sha = obj.getString("sha256");
                if (idx < 0 || idx >= arr.length()) {
                    throw new IllegalArgumentException("Chunk index out of range: " + idx);
                }
                chunks[idx] = new ChunkInfo(idx, offset, size, sha);
            }
        } catch (JSONException e) {
            throw new IllegalArgumentException("Failed to parse manifest JSON", e);
        }

        mChunks    = chunks;
        mTotalSha256 = totalSha256;
        mBitmap    = new byte[mChunks.length];

        // Ensure directories exist
        mVersionDir.mkdirs();
        mChunksDir.mkdirs();

        // Persist the manifest for reference
        File manifestFile = new File(mVersionDir, MANIFEST_FILE);
        if (!manifestFile.exists()) {
            writeFile(manifestFile, manifestJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        // Load existing bitmap from disk (resume partial download)
        loadBitmapFromDisk();

        Slog.i(TAG, "ChunkManager ready: version=" + version
                + " total=" + mChunks.length + " have=" + countOwned());
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Returns whether chunk {@code index} is locally available.
     */
    public synchronized boolean hasChunk(int index) {
        if (index < 0 || index >= mBitmap.length) return false;
        return mBitmap[index] == 0x01;
    }

    /**
     * Returns a copy of the in-memory chunk bitmap.
     * Each byte[i] is 0x01 if chunk i is held, 0x00 if missing.
     */
    public synchronized byte[] getChunkBitmap() {
        byte[] copy = new byte[mBitmap.length];
        System.arraycopy(mBitmap, 0, copy, 0, mBitmap.length);
        return copy;
    }

    /**
     * Saves a received chunk to disk after verifying its SHA-256 hash.
     *
     * @param index Zero-based chunk index.
     * @param data  Raw chunk bytes.
     * @return {@code true} if the data was saved successfully and hash matched;
     *         {@code false} if the index is out of range or the SHA-256 failed.
     */
    public boolean saveChunk(int index, byte[] data) {
        if (index < 0 || index >= mChunks.length) {
            Slog.w(TAG, "saveChunk: index out of range: " + index);
            return false;
        }
        if (data == null) {
            Slog.w(TAG, "saveChunk: null data for index " + index);
            return false;
        }

        // Verify SHA-256 before writing
        ChunkInfo info = mChunks[index];
        if (info == null) {
            Slog.w(TAG, "saveChunk: no manifest entry for index " + index);
            return false;
        }

        String computed = sha256Hex(data);
        if (!info.sha256.equalsIgnoreCase(computed)) {
            Slog.e(TAG, "saveChunk: SHA-256 mismatch for chunk " + index
                    + " expected=" + info.sha256 + " got=" + computed);
            return false;
        }

        // Write chunk file
        File chunkFile = chunkFile(index);
        if (!writeFile(chunkFile, data)) {
            Slog.e(TAG, "saveChunk: failed to write chunk file: " + chunkFile);
            return false;
        }

        // Update in-memory and on-disk bitmap
        synchronized (this) {
            mBitmap[index] = 0x01;
            persistBitmapLocked();
        }

        Slog.d(TAG, "saveChunk: saved index=" + index + " size=" + data.length);
        return true;
    }

    /**
     * Reads chunk {@code index} from disk.
     *
     * @return The raw chunk bytes, or {@code null} if the chunk is not
     *         available or an I/O error occurs.
     */
    public byte[] getChunk(int index) {
        if (!hasChunk(index)) return null;
        File chunkFile = chunkFile(index);
        if (!chunkFile.exists()) return null;
        try (FileInputStream fis = new FileInputStream(chunkFile)) {
            byte[] data = new byte[(int) chunkFile.length()];
            int read = 0;
            while (read < data.length) {
                int n = fis.read(data, read, data.length - read);
                if (n < 0) break;
                read += n;
            }
            return data;
        } catch (IOException e) {
            Slog.e(TAG, "getChunk: failed to read chunk " + index, e);
            return null;
        }
    }

    /**
     * Returns {@code true} when all chunks are locally available.
     */
    public synchronized boolean isComplete() {
        for (byte b : mBitmap) {
            if (b != 0x01) return false;
        }
        return mBitmap.length > 0;
    }

    /**
     * Assembles all chunks into {@code assembled.zip}, verifies the total
     * SHA-256, and returns the assembled file.
     *
     * Must only be called after {@link #isComplete()} returns {@code true}.
     *
     * @return The assembled {@link File}.
     * @throws IOException If assembly or hash verification fails.
     */
    public File getCompletedFile() throws IOException {
        if (!isComplete()) {
            throw new IOException("Cannot assemble: not all chunks present");
        }

        // Return cached assembled file if already done
        if (mAssembledFile.exists() && mAssembledFile.length() > 0) {
            Slog.i(TAG, "getCompletedFile: returning cached assembled.zip");
            return mAssembledFile;
        }

        Slog.i(TAG, "getCompletedFile: assembling " + mChunks.length + " chunks");

        // Assemble chunks in order
        try (FileOutputStream out = new FileOutputStream(mAssembledFile)) {
            for (int i = 0; i < mChunks.length; i++) {
                byte[] data = getChunk(i);
                if (data == null) {
                    mAssembledFile.delete();
                    throw new IOException("Chunk " + i + " disappeared during assembly");
                }
                out.write(data);
            }
        }

        // Verify total SHA-256 if manifest provides one
        if (mTotalSha256 != null && !mTotalSha256.isEmpty()) {
            String computed = sha256HexFile(mAssembledFile);
            if (!mTotalSha256.equalsIgnoreCase(computed)) {
                mAssembledFile.delete();
                throw new IOException("Assembled file SHA-256 mismatch: expected="
                        + mTotalSha256 + " got=" + computed);
            }
            Slog.i(TAG, "getCompletedFile: total SHA-256 verified OK");
        }

        Slog.i(TAG, "getCompletedFile: assembly complete, size=" + mAssembledFile.length());
        return mAssembledFile;
    }

    /**
     * Returns the total number of chunks in the manifest.
     */
    public int getTotalChunks() {
        return mChunks.length;
    }

    /**
     * Returns a list of chunk indices that are not yet locally available.
     */
    public synchronized List<Integer> getMissingChunkIndices() {
        List<Integer> missing = new ArrayList<>();
        for (int i = 0; i < mBitmap.length; i++) {
            if (mBitmap[i] != 0x01) missing.add(i);
        }
        return missing;
    }

    /**
     * Returns the {@link ChunkInfo} for a given index, or null if invalid.
     */
    public ChunkInfo getChunkInfo(int index) {
        if (index < 0 || index >= mChunks.length) return null;
        return mChunks[index];
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Returns the File for a given chunk index, e.g. chunks/003.chunk. */
    private File chunkFile(int index) {
        return new File(mChunksDir, String.format("%03d.chunk", index));
    }

    /** Counts how many chunks are currently owned. */
    private synchronized int countOwned() {
        int n = 0;
        for (byte b : mBitmap) if (b == 0x01) n++;
        return n;
    }

    /** Loads the persisted bitmap from disk into {@code mBitmap}. */
    private void loadBitmapFromDisk() {
        if (!mBitmapFile.exists()) return;
        try (FileInputStream fis = new FileInputStream(mBitmapFile)) {
            byte[] buf = new byte[mBitmap.length];
            int read = fis.read(buf);
            // Only copy as many bytes as we expect
            synchronized (this) {
                System.arraycopy(buf, 0, mBitmap, 0, Math.min(read, mBitmap.length));
            }
        } catch (IOException e) {
            Slog.w(TAG, "loadBitmapFromDisk: failed (starting fresh)", e);
        }

        // Validate: confirm chunk files actually exist for marked-present entries
        synchronized (this) {
            for (int i = 0; i < mBitmap.length; i++) {
                if (mBitmap[i] == 0x01 && !chunkFile(i).exists()) {
                    Slog.w(TAG, "Bitmap says have chunk " + i + " but file missing; clearing");
                    mBitmap[i] = 0x00;
                }
            }
        }
    }

    /** Writes the in-memory bitmap to disk. Must be called under {@code this} lock. */
    private void persistBitmapLocked() {
        writeFile(mBitmapFile, mBitmap);
    }

    /** Writes {@code data} to {@code file} atomically (write-to-tmp, rename). */
    private static boolean writeFile(File file, byte[] data) {
        File tmp = new File(file.getParent(), file.getName() + ".tmp");
        try (FileOutputStream fos = new FileOutputStream(tmp)) {
            fos.write(data);
            fos.flush();
        } catch (IOException e) {
            Slog.e(TAG, "writeFile: write failed: " + tmp, e);
            tmp.delete();
            return false;
        }
        if (!tmp.renameTo(file)) {
            // Fallback: non-atomic overwrite
            Slog.w(TAG, "writeFile: rename failed, falling back to direct write: " + file);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(data);
                fos.flush();
            } catch (IOException e2) {
                Slog.e(TAG, "writeFile: fallback write failed: " + file, e2);
                tmp.delete();
                return false;
            }
            tmp.delete();
        }
        return true;
    }

    /** Returns the lowercase hex SHA-256 of {@code data}. */
    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /** Returns the lowercase hex SHA-256 of the contents of {@code file}. */
    private static String sha256HexFile(File file) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buf = new byte[65536];
                int len;
                while ((len = fis.read(buf)) > 0) {
                    md.update(buf, 0, len);
                }
            }
            return bytesToHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 not available", e);
        }
    }

    /** Converts a byte array to a lowercase hex string. */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * Sanitizes a version string for safe use as a directory name.
     * Replaces any character that is not alphanumeric, '.', '-', or '_' with '_'.
     */
    private static String sanitizeVersion(String version) {
        if (version == null || version.isEmpty()) return "unknown";
        return version.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
