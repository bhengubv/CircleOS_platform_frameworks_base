package za.co.circleos.security;

import za.co.circleos.security.DmzAnalysisResult;
import za.co.circleos.security.ThreatIndicator;
import za.co.circleos.security.IFileDmzCallback;

interface ICircleFileDmz {
    // Submit a file for DMZ analysis. Returns a session ID.
    String submitFile(in ParcelFileDescriptor fileFd, String fileName, String mimeType, String sourceApp);
    // Get result synchronously (blocks)
    DmzAnalysisResult getResult(String sessionId);
    // Get sanitized (CDR) version of file
    ParcelFileDescriptor getSanitizedFile(String sessionId);
    // Release resources for a session
    void releaseSession(String sessionId);
    // Quarantine: list, delete, get details
    List<DmzAnalysisResult> listQuarantined();
    void deleteQuarantined(String sessionId);
    // Threat feeds
    boolean isHashKnownMalicious(String sha256Hex);
    boolean isDomainBlacklisted(String domain);
    boolean isIpBlacklisted(String ip);
    void triggerFeedUpdate();
    int getServiceVersion();
}
