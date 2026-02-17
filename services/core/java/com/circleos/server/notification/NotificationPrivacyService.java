package com.circleos.server.notification;

import android.app.Notification;
import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.SystemService;
import com.circleos.server.privacy.PrivacyLogger;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * CircleOS Notification Privacy Service
 * Redacts sensitive notification content for apps without notification permission
 * and prevents notification listeners from accessing content of protected apps.
 */
public class NotificationPrivacyService extends SystemService {

    private static final String TAG = "CircleNotifPrivacy";

    // Apps whose notification content is always redacted from listeners
    private static final Set<String> SENSITIVE_APPS = new HashSet<>(Arrays.asList(
        "com.android.contacts",
        "com.android.dialer",
        "com.android.messaging"
    ));

    private HandlerThread mHandlerThread;
    private Handler mHandler;
    private PrivacyLogger mLogger;

    public NotificationPrivacyService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        Log.i(TAG, "CircleNotificationPrivacyService starting");
        mHandlerThread = new HandlerThread("CircleNotifPrivacy");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());
        mLogger = new PrivacyLogger(getContext());
        publishBinderService("circle.notification_privacy", new NotificationPrivacyImpl());
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            Log.i(TAG, "Boot completed — notification privacy active");
        }
    }

    /**
     * Returns true if the notification content for this package should be redacted
     * when delivered to third-party notification listeners.
     */
    public boolean shouldRedactContent(String packageName) {
        return SENSITIVE_APPS.contains(packageName);
    }

    /**
     * Returns a redacted version of the notification with sensitive text replaced.
     */
    public Notification redactNotification(Notification original, String packageName) {
        mLogger.log(packageName, "NOTIFICATION", "REDACTED", null);
        Notification.Builder builder = new Notification.Builder(getContext(), original)
            .setContentTitle("New message")
            .setContentText("Content hidden for privacy")
            .setTicker(null);
        return builder.build();
    }

    private class NotificationPrivacyImpl extends android.os.Binder {
        // Binder stub — full AIDL interface defined separately
    }

    public static final class Lifecycle extends SystemService {
        private NotificationPrivacyService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new NotificationPrivacyService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }
}
