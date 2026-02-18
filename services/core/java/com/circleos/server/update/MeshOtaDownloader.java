/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Phase-4 mesh-delivery OTA downloader.
 *
 * <p>Fetches a chunk manifest from the SleptOn API, discovers local peers via
 * mDNS ({@value #NSD_SERVICE_TYPE}), then downloads each 1 MB chunk preferring
 * a peer that already has the chunk over a direct CDN fallback.  Once all
 * chunks are assembled the package SHA-256 is verified against the manifest.
 *
 * <p>After a successful download this class also starts a lightweight TCP
 * chunk-server so that <em>other</em> devices on the same network can fetch
 * chunks from this device, reducing CDN bandwidth.
 *
 * <h3>Peer protocol (TCP port {@value #CHUNK_PORT})</h3>
 * <pre>
 * Request  – 4-byte big-endian chunk index
 * Response – 4-byte big-endian chunk length, then raw bytes
 *            length == 0  → chunk not available on this peer
 * </pre>
 */
public class MeshOtaDownloader {

    private static final String TAG = "MeshOtaDownloader";

    // ── mDNS constants ────────────────────────────────────────────────────────
    /** mDNS service type advertised / browsed by all CircleOS devices. */
    private static final String NSD_SERVICE_TYPE      = "_circleos_ota._tcp.";
    private static final String NSD_SERVICE_NAME      = "CircleOS_OTA_Chunk";
    /** mDNS TXT key that carries the OTA version string. */
    private static final String NSD_TXT_VERSION_KEY   = "v";

    // ── Networking ────────────────────────────────────────────────────────────
    /** Port on which each device's chunk-server listens. */
    static final int  CHUNK_PORT               = 7369;
    /** How long to wait for mDNS peer responses before falling back to CDN. */
    private static final long PEER_DISCOVERY_MS = 8_000L;
    /** Per-chunk connection/read timeout when downloading from a peer. */
    private static final int  PEER_TIMEOUT_MS   = 15_000;
    /** Per-chunk read timeout for CDN downloads. */
    private static final int  CDN_TIMEOUT_MS    = 60_000;

    // ── SleptOn API ───────────────────────────────────────────────────────────
    /** Base URL of the SleptOn API. Overridable for testing. */
    static String API_BASE_URL = "https://slepton.co.za";

    // ── Implementation ────────────────────────────────────────────────────────
    private static final String UPDATE_DIR = "/data/system/circleos_update";

    // ── Inner types ───────────────────────────────────────────────────────────

    /** Manifest returned by GET /api/os/releases/{version}/chunks. */
    static final class ChunkManifest {
        final String   version;
        final String   pkg;          // "full" or "delta_X.Y.Z"
        final long     totalSize;
        final int      chunkSize;
        final int      chunkCount;
        final String   packageSha256;
        final String   downloadUrl;  // CDN fallback URL (full package)
        final ChunkInfo[] chunks;

        ChunkManifest(String version, String pkg, long totalSize, int chunkSize,
                int chunkCount, String packageSha256, String downloadUrl, ChunkInfo[] chunks) {
            this.version      = version;
            this.pkg          = pkg;
            this.totalSize    = totalSize;
            this.chunkSize    = chunkSize;
            this.chunkCount   = chunkCount;
            this.packageSha256 = packageSha256;
            this.downloadUrl  = downloadUrl;
            this.chunks       = chunks;
        }

        static ChunkManifest fromJson(JSONObject o) throws Exception {
            JSONArray ja    = o.getJSONArray("chunks");
            ChunkInfo[] arr = new ChunkInfo[ja.length()];
            for (int i = 0; i < ja.length(); i++) {
                arr[i] = ChunkInfo.fromJson(ja.getJSONObject(i));
            }
            return new ChunkManifest(
                    o.getString("version"),
                    o.getString("package"),
                    o.getLong("totalSize"),
                    o.getInt("chunkSize"),
                    o.getInt("chunkCount"),
                    o.getString("packageSha256"),
                    o.getString("downloadUrl"),
                    arr);
        }
    }

    /** Single-chunk descriptor. */
    static final class ChunkInfo {
        final int    index;
        final long   offset;
        final int    size;
        final String sha256;

        ChunkInfo(int index, long offset, int size, String sha256) {
            this.index  = index;
            this.offset = offset;
            this.size   = size;
            this.sha256 = sha256;
        }

        static ChunkInfo fromJson(JSONObject o) throws Exception {
            return new ChunkInfo(
                    o.getInt("index"),
                    o.getLong("offset"),
                    o.getInt("size"),
                    o.getString("sha256"));
        }
    }

    /** Callback for progress updates (0–100). */
    public interface ProgressCallback {
        void onProgress(int percent);
    }

    // ── Fields ────────────────────────────────────────────────────────────────

    private final Context          mContext;
    private final NsdManager       mNsdManager;

    /** Running chunk-server, if started after a successful download. */
    private volatile ChunkServer   mChunkServer;

    // ── Constructor ───────────────────────────────────────────────────────────

    public MeshOtaDownloader(Context context) {
        mContext    = context;
        mNsdManager = (NsdManager) context.getSystemService(Context.NSD_SERVICE);
    }

    // ── Public entry point ────────────────────────────────────────────────────

    /**
     * Downloads the full OTA package for {@code version} from the mesh + CDN,
     * assembles it, verifies the SHA-256 hash and returns the ready-to-install
     * {@link File}.
     *
     * <p>Blocks the calling thread until complete or an exception is thrown.
     *
     * @param version  Version string (e.g. {@code "14.1.2"}).
     * @param channel  Release channel ({@code "stable"}, {@code "beta"}, etc.).
     * @param callback Optional progress listener (may be null).
     * @return Assembled OTA zip {@link File}.
     * @throws IOException on any unrecoverable error.
     */
    public File download(String version, String channel, ProgressCallback callback)
            throws IOException {
        return downloadInternal(version, channel, "full", callback);
    }

    /**
     * Downloads a <em>delta</em> OTA package that upgrades from {@code fromVersion}
     * to {@code toVersion}.  Uses the same mesh-first + CDN-fallback strategy as
     * {@link #download(String, String, ProgressCallback)}.
     *
     * @param fromVersion Current OS version on the device.
     * @param toVersion   Target version to upgrade to.
     * @param channel     Release channel.
     * @param callback    Optional progress listener.
     * @return Assembled delta OTA zip {@link File}.
     * @throws IOException on any unrecoverable error.
     */
    public File downloadDelta(String fromVersion, String toVersion, String channel,
            ProgressCallback callback) throws IOException {
        return downloadInternal(toVersion, channel, "delta_" + fromVersion, callback);
    }

    // ── Shared download implementation ────────────────────────────────────────

    private File downloadInternal(String version, String channel, String packageType,
            ProgressCallback callback) throws IOException {

        // 1. Fetch chunk manifest
        Log.i(TAG, "Fetching chunk manifest for v" + version + " pkg=" + packageType
                + " [" + channel + "]");
        ChunkManifest manifest = fetchManifest(version, channel, packageType);
        Log.i(TAG, "Manifest: " + manifest.chunkCount + " chunks, total "
                + manifest.totalSize + " bytes");

        // 2. Discover peers that already hold this version's chunks
        List<InetSocketAddress> peers = discoverPeers(version);
        Log.i(TAG, "Discovered " + peers.size() + " peer(s) with OTA chunks");

        // 3. Prepare destination file
        File updateDir = new File(UPDATE_DIR);
        if (!updateDir.exists() && !updateDir.mkdirs()) {
            throw new IOException("Cannot create update dir: " + UPDATE_DIR);
        }
        String safeVer  = version.replaceAll("[^a-zA-Z0-9._-]", "_");
        String safePkg  = packageType.replaceAll("[^a-zA-Z0-9._-]", "_");
        String safeName = "circleos_mesh_" + safeVer + "_" + safePkg + ".zip";
        File destFile = new File(updateDir, safeName);

        // Pre-allocate the file to totalSize
        try (RandomAccessFile raf = new RandomAccessFile(destFile, "rw")) {
            raf.setLength(manifest.totalSize);
        }

        MessageDigest pkgDigest = sha256Digest();
        int totalChunks = manifest.chunkCount;
        int downloaded  = 0;

        // 4. Download each chunk
        for (ChunkInfo chunk : manifest.chunks) {
            byte[] data = null;

            // Try peers first
            for (InetSocketAddress peer : peers) {
                data = downloadChunkFromPeer(peer, chunk.index, chunk.size);
                if (data != null) {
                    Log.d(TAG, "Chunk " + chunk.index + " from peer " + peer.getHostString());
                    break;
                }
            }

            // Fall back to CDN
            if (data == null) {
                Log.d(TAG, "Chunk " + chunk.index + " from CDN");
                data = downloadChunkFromCdn(manifest.downloadUrl, chunk.offset, chunk.size);
            }

            if (data == null || data.length == 0) {
                throw new IOException("Failed to fetch chunk " + chunk.index);
            }

            // Verify per-chunk SHA-256
            String actual = hex(sha256(data));
            if (!actual.equalsIgnoreCase(chunk.sha256)) {
                throw new IOException("SHA-256 mismatch for chunk " + chunk.index
                        + " expected=" + chunk.sha256 + " actual=" + actual);
            }

            // Write at correct offset
            try (RandomAccessFile raf = new RandomAccessFile(destFile, "rw")) {
                raf.seek(chunk.offset);
                raf.write(data);
            }

            // Accumulate for package digest
            pkgDigest.update(data);

            downloaded++;
            if (callback != null) {
                callback.onProgress((downloaded * 100) / totalChunks);
            }
        }

        // 5. Verify package SHA-256
        String pkgActual = hex(pkgDigest.digest());
        if (!pkgActual.equalsIgnoreCase(manifest.packageSha256)) {
            destFile.delete();
            throw new IOException("Package SHA-256 mismatch: expected="
                    + manifest.packageSha256 + " actual=" + pkgActual);
        }

        Log.i(TAG, "Mesh OTA assembled and verified: " + destFile.getAbsolutePath());

        // 6. Start chunk server so other devices can pull from us
        startChunkServer(destFile, manifest, version);

        return destFile;
    }

    /** Stop the chunk-server if running (call when update is installed). */
    public void stopChunkServer() {
        ChunkServer srv = mChunkServer;
        if (srv != null) {
            srv.stop();
            mChunkServer = null;
        }
    }

    // ── Manifest fetch ────────────────────────────────────────────────────────

    private ChunkManifest fetchManifest(String version, String channel,
            String packageType) throws IOException {
        String urlStr = API_BASE_URL + "/api/os/releases/" + version
                + "/chunks?channel=" + channel + "&package=" + packageType;
        Log.d(TAG, "GET " + urlStr);
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(30_000);
        conn.setRequestProperty("Accept", "application/json");
        try {
            int code = conn.getResponseCode();
            if (code != 200) {
                throw new IOException("Chunk manifest returned HTTP " + code);
            }
            byte[] body = conn.getInputStream().readAllBytes();
            JSONObject json = new JSONObject(new String(body, "UTF-8"));
            return ChunkManifest.fromJson(json);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to parse chunk manifest: " + e.getMessage(), e);
        } finally {
            conn.disconnect();
        }
    }

    // ── mDNS peer discovery ───────────────────────────────────────────────────

    /**
     * Discovers peers on the local network that advertise a chunk-server for
     * {@code version} via mDNS.  Waits up to {@value #PEER_DISCOVERY_MS} ms.
     */
    private List<InetSocketAddress> discoverPeers(String version) {
        if (mNsdManager == null) {
            Log.w(TAG, "NsdManager not available — skipping peer discovery");
            return Collections.emptyList();
        }

        List<InetSocketAddress> found = new ArrayList<>();
        CountDownLatch latch = new CountDownLatch(1);

        NsdManager.DiscoveryListener discovery = new NsdManager.DiscoveryListener() {
            @Override public void onStartDiscoveryFailed(String type, int errorCode) {
                Log.w(TAG, "mDNS discovery failed to start: " + errorCode);
                latch.countDown();
            }
            @Override public void onStopDiscoveryFailed(String type, int errorCode) {}
            @Override public void onDiscoveryStarted(String type) {
                Log.d(TAG, "mDNS discovery started for " + type);
            }
            @Override public void onDiscoveryStopped(String type) {}

            @Override
            public void onServiceFound(NsdServiceInfo info) {
                mNsdManager.resolveService(info, new NsdManager.ResolveListener() {
                    @Override public void onResolveFailed(NsdServiceInfo i, int errorCode) {
                        Log.d(TAG, "Resolve failed for " + i.getServiceName() + ": " + errorCode);
                    }
                    @Override public void onServiceResolved(NsdServiceInfo resolved) {
                        // Check TXT record version key
                        byte[] vAttr = resolved.getAttributes().get(NSD_TXT_VERSION_KEY);
                        String peerVersion = (vAttr != null) ? new String(vAttr) : "";
                        if (!version.equals(peerVersion)) {
                            Log.d(TAG, "Peer has v" + peerVersion + ", need v" + version
                                    + " — skip");
                            return;
                        }
                        InetSocketAddress addr = new InetSocketAddress(
                                resolved.getHost(), resolved.getPort());
                        Log.i(TAG, "Found peer with v" + version + " at " + addr);
                        synchronized (found) {
                            found.add(addr);
                        }
                    }
                });
            }

            @Override public void onServiceLost(NsdServiceInfo info) {}
        };

        try {
            mNsdManager.discoverServices(NSD_SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discovery);
            // Wait for the discovery window
            latch.await(PEER_DISCOVERY_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            try {
                mNsdManager.stopServiceDiscovery(discovery);
            } catch (Exception ignored) {}
        }

        return Collections.unmodifiableList(found);
    }

    // ── Peer chunk download ───────────────────────────────────────────────────

    /**
     * Attempts to fetch a single chunk from a peer's chunk-server.
     *
     * @return Raw chunk bytes, or {@code null} if the peer cannot provide the chunk.
     */
    private byte[] downloadChunkFromPeer(InetSocketAddress peer, int chunkIndex, int chunkSize) {
        try (Socket s = new Socket()) {
            s.connect(peer, PEER_TIMEOUT_MS);
            s.setSoTimeout(PEER_TIMEOUT_MS);

            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            DataInputStream  in  = new DataInputStream(s.getInputStream());

            // Send chunk index (4 bytes big-endian)
            out.writeInt(chunkIndex);
            out.flush();

            // Read response length
            int length = in.readInt();
            if (length <= 0) {
                Log.d(TAG, "Peer " + peer.getHostString() + " has no chunk " + chunkIndex);
                return null;
            }

            // Read chunk data
            byte[] buf = new byte[length];
            int read = 0;
            while (read < length) {
                int n = in.read(buf, read, length - read);
                if (n < 0) throw new IOException("Peer closed connection early");
                read += n;
            }
            return buf;

        } catch (Exception e) {
            Log.d(TAG, "Peer " + peer.getHostString() + " chunk " + chunkIndex
                    + " failed: " + e.getMessage());
            return null;
        }
    }

    // ── CDN chunk download ────────────────────────────────────────────────────

    /**
     * Downloads a single chunk from the CDN using an HTTP Range request.
     */
    private byte[] downloadChunkFromCdn(String packageUrl, long offset, int size)
            throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(packageUrl).openConnection();
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(CDN_TIMEOUT_MS);
        // Request the exact byte range for this chunk
        conn.setRequestProperty("Range",
                "bytes=" + offset + "-" + (offset + size - 1));
        try {
            int code = conn.getResponseCode();
            if (code != 206 && code != 200) {
                throw new IOException("CDN returned HTTP " + code + " for chunk at offset " + offset);
            }
            try (InputStream is = conn.getInputStream()) {
                byte[] buf = new byte[size];
                int read = 0;
                while (read < size) {
                    int n = is.read(buf, read, size - read);
                    if (n < 0) break;
                    read += n;
                }
                if (read != size) {
                    throw new IOException("CDN short read: expected " + size + " got " + read);
                }
                return buf;
            }
        } finally {
            conn.disconnect();
        }
    }

    // ── Chunk server (serve to peers) ─────────────────────────────────────────

    private void startChunkServer(File otaFile, ChunkManifest manifest, String version) {
        if (mChunkServer != null) return;
        try {
            ChunkServer srv = new ChunkServer(otaFile, manifest, mNsdManager, version);
            srv.start();
            mChunkServer = srv;
            Log.i(TAG, "Chunk server started on port " + CHUNK_PORT);
        } catch (Exception e) {
            Log.w(TAG, "Failed to start chunk server (non-fatal): " + e.getMessage());
        }
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    private static MessageDigest sha256Digest() throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new IOException("SHA-256 not available", e);
        }
    }

    private static byte[] sha256(byte[] data) throws IOException {
        MessageDigest md = sha256Digest();
        return md.digest(data);
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Inner class: ChunkServer
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Minimal TCP server that serves OTA chunks to peers.
     * Registers an mDNS service so other devices can discover it.
     */
    static final class ChunkServer extends Thread {

        private final File          mOtaFile;
        private final ChunkManifest mManifest;
        private final NsdManager    mNsdManager;
        private final String        mVersion;

        private volatile boolean    mRunning = true;
        private ServerSocket        mServerSocket;
        private NsdServiceInfo      mNsdInfo;

        ChunkServer(File otaFile, ChunkManifest manifest, NsdManager nsdManager, String version)
                throws IOException {
            super("MeshOtaChunkServer");
            setDaemon(true);
            mOtaFile    = otaFile;
            mManifest   = manifest;
            mNsdManager = nsdManager;
            mVersion    = version;

            mServerSocket = new ServerSocket(CHUNK_PORT);
        }

        @Override
        public void start() {
            super.start();
            registerMdns();
        }

        void stop() {
            mRunning = false;
            try {
                if (mServerSocket != null) mServerSocket.close();
            } catch (IOException ignored) {}
            if (mNsdManager != null && mNsdInfo != null) {
                try {
                    mNsdManager.unregisterService(new NsdManager.RegistrationListener() {
                        @Override public void onRegistrationFailed(NsdServiceInfo i, int e) {}
                        @Override public void onUnregistrationFailed(NsdServiceInfo i, int e) {}
                        @Override public void onServiceRegistered(NsdServiceInfo i) {}
                        @Override public void onServiceUnregistered(NsdServiceInfo i) {
                            Log.d(TAG, "mDNS chunk service unregistered");
                        }
                    });
                } catch (Exception ignored) {}
            }
        }

        @Override
        public void run() {
            Log.i(TAG, "ChunkServer running on port " + CHUNK_PORT);
            while (mRunning) {
                try {
                    Socket client = mServerSocket.accept();
                    new Thread(() -> handleClient(client), "MeshOtaClient").start();
                } catch (IOException e) {
                    if (mRunning) Log.w(TAG, "Accept error: " + e.getMessage());
                }
            }
        }

        private void handleClient(Socket client) {
            try {
                client.setSoTimeout(10_000);
                DataInputStream  in  = new DataInputStream(client.getInputStream());
                DataOutputStream out = new DataOutputStream(client.getOutputStream());

                int chunkIndex = in.readInt();

                if (chunkIndex < 0 || chunkIndex >= mManifest.chunkCount) {
                    out.writeInt(0);
                    out.flush();
                    return;
                }

                ChunkInfo ci = mManifest.chunks[chunkIndex];
                byte[] data  = new byte[ci.size];

                try (RandomAccessFile raf = new RandomAccessFile(mOtaFile, "r")) {
                    raf.seek(ci.offset);
                    raf.readFully(data);
                }

                out.writeInt(data.length);
                out.write(data);
                out.flush();
                Log.d(TAG, "Served chunk " + chunkIndex + " (" + data.length + " bytes) to "
                        + client.getInetAddress().getHostAddress());

            } catch (Exception e) {
                Log.d(TAG, "Client handler error: " + e.getMessage());
            } finally {
                try { client.close(); } catch (IOException ignored) {}
            }
        }

        private void registerMdns() {
            if (mNsdManager == null) return;
            NsdServiceInfo info = new NsdServiceInfo();
            info.setServiceName(NSD_SERVICE_NAME);
            info.setServiceType(NSD_SERVICE_TYPE);
            info.setPort(CHUNK_PORT);
            info.setAttribute(NSD_TXT_VERSION_KEY, mVersion);
            mNsdInfo = info;

            mNsdManager.registerService(info, NsdManager.PROTOCOL_DNS_SD,
                    new NsdManager.RegistrationListener() {
                        @Override public void onRegistrationFailed(NsdServiceInfo i, int e) {
                            Log.w(TAG, "mDNS registration failed: " + e);
                        }
                        @Override public void onUnregistrationFailed(NsdServiceInfo i, int e) {}
                        @Override public void onServiceRegistered(NsdServiceInfo i) {
                            Log.i(TAG, "mDNS chunk service registered: " + i.getServiceName());
                        }
                        @Override public void onServiceUnregistered(NsdServiceInfo i) {}
                    });
        }
    }
}
