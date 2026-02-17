package za.co.circleos.security;

import za.co.circleos.security.QuarantineRecord;

interface ICircleQuarantine {
    // List all quarantined files
    List<QuarantineRecord> listAll();
    // Get details for one record
    QuarantineRecord getRecord(String quarantineId);
    // Delete a quarantined file permanently
    boolean deleteRecord(String quarantineId);
    // Delete all quarantined files
    void deleteAll();
    // Restore a quarantined file to a specified path (user has accepted risk)
    boolean restore(String quarantineId, String destinationPath);
    // Submit record to Community Defense (anonymized IOCs only)
    void submitToCommunity(String quarantineId);
    // Get total quarantine size in bytes
    long getQuarantineSize();
    int getServiceVersion();
}
