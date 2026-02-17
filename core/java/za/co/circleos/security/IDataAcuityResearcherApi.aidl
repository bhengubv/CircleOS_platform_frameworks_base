package za.co.circleos.security;

import za.co.circleos.security.AttackCampaign;
import za.co.circleos.security.IocBundle;
import za.co.circleos.security.QuarantineRecord;

/**
 * Data Acuity Researcher API — exposes threat intelligence to authorized researchers.
 * Requires RESEARCHER_API permission (signature|privileged).
 *
 * Service name: "circle.researcher_api"
 */
interface IDataAcuityResearcherApi {
    // Campaigns
    List<AttackCampaign> listCampaigns(int maxResults);
    AttackCampaign getCampaign(String campaignId);

    // IOC bundles — STIX 2.1 compatible JSON
    IocBundle getIocBundle(String campaignId);
    IocBundle getAllIocs(long sinceEpochMs, int maxResults);

    // Feed subscription (polling)
    IocBundle pollNewIocs(long sinceEpochMs);

    // Infrastructure
    List<String> getRelatedInfrastructure(String ipOrDomain);
    List<String> predictRelatedInfrastructure(String campaignId);

    // Stats
    int getTotalCampaigns();
    int getTotalIocs();
    int getServiceVersion();
}
