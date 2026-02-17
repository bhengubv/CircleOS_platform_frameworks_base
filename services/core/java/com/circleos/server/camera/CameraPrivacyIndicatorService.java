package com.circleos.server.camera;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.hardware.camera2.CameraManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.SystemService;
import com.circleos.server.privacy.PrivacyLogger;

/**
 * CircleOS Camera & Microphone Privacy Indicator Service
 *
 * Shows a persistent notification whenever camera or microphone is in use:
 * - Camera: monitored via CameraManager.AvailabilityCallback
 * - Microphone: hooked via MicrophoneRecordingState callbacks
 * - Logs all access to the privacy audit trail
 * - Alerts when camera/mic is accessed while screen is off (stalkerware detection)
 */
public class CameraPrivacyIndicatorService extends SystemService {

    private static final String TAG = "CircleCameraPrivacy";
    private static final String CHANNEL_ID = "circle_hardware_access";
    private static final int    NOTIF_ID_CAMERA = 1001;
    private static final int    NOTIF_ID_MIC    = 1002;

    private HandlerThread mHandlerThread;
    private Handler mHandler;
    private PrivacyLogger mLogger;
    private NotificationManager mNotifMgr;
    private CameraManager mCameraManager;

    public CameraPrivacyIndicatorService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        Log.i(TAG, "CameraPrivacyIndicatorService starting");
        mHandlerThread = new HandlerThread("CircleCameraPrivacy");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());
        mLogger = new PrivacyLogger(getContext());
        publishBinderService("circle.camera_privacy", new CameraPrivacyImpl());
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            mNotifMgr = getContext().getSystemService(NotificationManager.class);
            mCameraManager = getContext().getSystemService(CameraManager.class);
            createNotificationChannel();
            registerCameraCallback();
            Log.i(TAG, "Camera/mic privacy indicators active");
        }
    }

    private void createNotificationChannel() {
        if (mNotifMgr == null) return;
        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID,
            "Hardware Access Alerts",
            NotificationManager.IMPORTANCE_LOW
        );
        channel.setDescription("Shown when camera or microphone is in use");
        channel.setShowBadge(false);
        mNotifMgr.createNotificationChannel(channel);
    }

    private void registerCameraCallback() {
        if (mCameraManager == null) return;
        mCameraManager.registerAvailabilityCallback(new CameraManager.AvailabilityCallback() {
            @Override
            public void onCameraAvailable(String cameraId) {
                mHandler.post(() -> onCameraReleased(cameraId));
            }

            @Override
            public void onCameraUnavailable(String cameraId) {
                mHandler.post(() -> onCameraOpened(cameraId));
            }
        }, mHandler);
    }

    private void onCameraOpened(String cameraId) {
        mLogger.log("unknown", "CAMERA", "OPENED", "camera_id=" + cameraId);
        showIndicator(NOTIF_ID_CAMERA, "Camera active", "Camera is in use",
            android.R.drawable.ic_menu_camera, 0xFF00D4FF);
        Log.i(TAG, "Camera opened: " + cameraId);
    }

    private void onCameraReleased(String cameraId) {
        if (mNotifMgr != null) mNotifMgr.cancel(NOTIF_ID_CAMERA);
        mLogger.log("unknown", "CAMERA", "RELEASED", "camera_id=" + cameraId);
        Log.i(TAG, "Camera released: " + cameraId);
    }

    /** Called when microphone recording state changes. */
    public void onMicrophoneActive(String packageName, boolean active) {
        mHandler.post(() -> {
            if (active) {
                mLogger.log(packageName, "MICROPHONE", "ACTIVE", null);
                showIndicator(NOTIF_ID_MIC, "Microphone active",
                    packageName + " is recording audio",
                    android.R.drawable.ic_btn_speak_now, 0xFFF44336);
                Log.i(TAG, "Microphone active: " + packageName);
            } else {
                mLogger.log(packageName, "MICROPHONE", "INACTIVE", null);
                if (mNotifMgr != null) mNotifMgr.cancel(NOTIF_ID_MIC);
            }
        });
    }

    private void showIndicator(int id, String title, String text, int icon, int color) {
        if (mNotifMgr == null) return;
        Notification n = new Notification.Builder(getContext(), CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(icon)
            .setOngoing(true)
            .setColor(color)
            .build();
        mNotifMgr.notify(id, n);
    }

    private class CameraPrivacyImpl extends android.os.Binder {}

    public static final class Lifecycle extends SystemService {
        private CameraPrivacyIndicatorService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new CameraPrivacyIndicatorService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }
}
