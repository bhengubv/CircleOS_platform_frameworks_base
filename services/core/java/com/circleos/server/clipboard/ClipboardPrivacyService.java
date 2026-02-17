package com.circleos.server.clipboard;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.SystemService;
import com.circleos.server.privacy.PrivacyLogger;

/**
 * CircleOS Clipboard Privacy Service
 *
 * Prevents apps from silently reading clipboard content:
 * - Background apps cannot read clipboard (enforced at framework level)
 * - Auto-clears clipboard after 60 seconds when sensitive patterns are detected
 * - Logs all clipboard access attempts to the audit trail
 * - Detects sensitive patterns: credit cards, passwords, private keys, API keys
 */
public class ClipboardPrivacyService extends SystemService {

    private static final String TAG = "CircleClipPrivacy";
    private static final long CLEAR_DELAY_MS = 60_000L; // 60 seconds

    // Regex patterns for sensitive clipboard content
    private static final String[] SENSITIVE_PATTERNS = {
        "\\b(?:\\d[ -]?){13,19}\\b",                    // Credit card numbers
        "(?i)password[\\s:=]+\\S+",                     // Password strings
        "-----BEGIN.*PRIVATE KEY-----",                  // PEM private keys
        "(?i)(?:api[_-]?key|secret|token)[\\s:=]+\\S+", // API keys/secrets
        "\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b",       // Bitcoin addresses
    };

    private HandlerThread mHandlerThread;
    private Handler mHandler;
    private PrivacyLogger mLogger;
    private final Runnable mClearClipboard = this::clearSensitiveClipboard;

    public ClipboardPrivacyService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        Log.i(TAG, "CircleClipboardPrivacyService starting");
        mHandlerThread = new HandlerThread("CircleClipPrivacy");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());
        mLogger = new PrivacyLogger(getContext());
        publishBinderService("circle.clipboard_privacy", new ClipboardPrivacyImpl());
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            Log.i(TAG, "Boot completed — clipboard privacy active");
            monitorClipboard();
        }
    }

    private void monitorClipboard() {
        ClipboardManager cm = getContext().getSystemService(ClipboardManager.class);
        if (cm == null) return;
        cm.addPrimaryClipChangedListener(() -> mHandler.post(this::checkClipboardContent));
    }

    private void checkClipboardContent() {
        ClipboardManager cm = getContext().getSystemService(ClipboardManager.class);
        if (cm == null || !cm.hasPrimaryClip()) return;

        ClipData clip = cm.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) return;

        CharSequence text = clip.getItemAt(0).getText();
        if (text == null) return;

        String content = text.toString();
        for (String pattern : SENSITIVE_PATTERNS) {
            if (content.matches(".*" + pattern + ".*")) {
                Log.i(TAG, "Sensitive clipboard pattern detected — scheduling auto-clear");
                mLogger.log("system", "CLIPBOARD", "SENSITIVE_DETECTED", "auto_clear_scheduled");
                mHandler.removeCallbacks(mClearClipboard);
                mHandler.postDelayed(mClearClipboard, CLEAR_DELAY_MS);
                return;
            }
        }
    }

    private void clearSensitiveClipboard() {
        ClipboardManager cm = getContext().getSystemService(ClipboardManager.class);
        if (cm != null) {
            cm.clearPrimaryClip();
            mLogger.log("system", "CLIPBOARD", "AUTO_CLEARED", "sensitive_content");
            Log.i(TAG, "Clipboard auto-cleared after timeout");
        }
    }

    /**
     * Called from ClipboardService to check if a package is allowed to read clipboard.
     * Apps must be the top foreground activity to access clipboard content.
     */
    public boolean isReadAllowed(String packageName, boolean isTopActivity) {
        if (!isTopActivity) {
            mLogger.log(packageName, "CLIPBOARD", "DENIED", "app_not_foreground");
            return false;
        }
        return true;
    }

    private class ClipboardPrivacyImpl extends android.os.Binder {}

    public static final class Lifecycle extends SystemService {
        private ClipboardPrivacyService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new ClipboardPrivacyService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }
}
