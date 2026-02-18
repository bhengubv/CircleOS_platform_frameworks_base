/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * AIDL interface for the Circle OS Notification Privacy Manager.
 * Service name: "circle.notification_privacy"
 */
package android.circleos;

/**
 * Binder interface for NotificationPrivacyService.
 *
 * Governs which notification content is visible to third-party
 * NotificationListenerService implementations.
 *
 * Callers require com.circleos.permission.MANAGE_PRIVACY.
 *
 * Hook point in AOSP: NotificationManagerService.notifyPostedLocked() —
 * call shouldRedactForListener(listenerPkg, sourcePkg) before delivering
 * the StatusBarNotification to each registered listener. If true, replace
 * the notification with the redacted copy returned by the service.
 */
interface INotificationPrivacyManager {

    /**
     * Returns true if the notification body posted by {@code sourcePackage}
     * should be redacted before delivery to any third-party listener.
     */
    boolean shouldRedactContent(String sourcePackage);

    /**
     * Returns true if {@code listenerPackage} is blocked from receiving
     * any notifications posted by {@code sourcePackage}.
     */
    boolean isListenerBlockedForSource(String listenerPackage, String sourcePackage);

    /**
     * Marks {@code packageName} as a sensitive app whose notification
     * content is always redacted for third-party listeners.
     */
    void addSensitiveApp(String packageName);

    /**
     * Removes the sensitive-app designation for {@code packageName}.
     * No-op if the package was not in the sensitive list.
     */
    void removeSensitiveApp(String packageName);

    /**
     * Returns the full list of package names currently marked sensitive.
     */
    List<String> getSensitiveApps();

    /**
     * Blocks all notifications from {@code sourcePackage} reaching
     * {@code listenerPackage}.
     */
    void blockListenerForSource(String listenerPackage, String sourcePackage);

    /**
     * Removes a previously set listener block.
     */
    void unblockListenerForSource(String listenerPackage, String sourcePackage);
}
