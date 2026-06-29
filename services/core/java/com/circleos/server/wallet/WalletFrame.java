package com.circleos.server.wallet;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Pure NFC message framing + canonical offer bytes for the SDPKT wallet — no
 * Android dependencies, unit-testable off-device. Wire message is
 * [1-byte type][UTF-8 JSON payload], base64-encoded. This is the single source
 * of truth for the on-wire framing used by ShongololoWalletService's NFC
 * transfer state machine.
 */
final class WalletFrame {

    static final int MSG_DISCOVER = 0x01;
    static final int MSG_HELLO    = 0x02;
    static final int MSG_OFFER    = 0x03;
    static final int MSG_ACCEPTED = 0x04;
    static final int MSG_ERROR    = 0x05;

    private WalletFrame() {}

    /** Encode [type][json] -> base64 string. */
    static String frame(int type, String json) {
        byte[] j = (json == null) ? new byte[0] : json.getBytes(StandardCharsets.UTF_8);
        byte[] msg = new byte[1 + j.length];
        msg[0] = (byte) type;
        System.arraycopy(j, 0, msg, 1, j.length);
        return Base64.getEncoder().encodeToString(msg);
    }

    static final class Decoded {
        final int type;
        final String json;
        Decoded(int type, String json) { this.type = type; this.json = json; }
    }

    /** Decode base64 -> {type, json}; null if malformed or empty. */
    static Decoded decode(String b64) {
        if (b64 == null || b64.isEmpty()) return null;
        byte[] raw;
        try { raw = Base64.getDecoder().decode(b64.trim()); }
        catch (Throwable t) { return null; }
        if (raw.length < 1) return null;
        int type = raw[0] & 0xff;
        String json = (raw.length > 1)
                ? new String(raw, 1, raw.length - 1, StandardCharsets.UTF_8) : "";
        return new Decoded(type, json);
    }

    /** Canonical bytes a transfer offer is signed over. MUST be byte-identical
     *  on the signer and the verifier, or signatures will never validate. */
    static byte[] offerBytes(String rsid, long amountCents, String memo) {
        return ("SDPKT|" + (rsid == null ? "" : rsid) + "|" + amountCents + "|"
                + (memo == null ? "" : memo)).getBytes(StandardCharsets.UTF_8);
    }
}
