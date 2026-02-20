package za.co.circleos.security;

import za.co.circleos.security.DmzAnalysisResult;

oneway interface IFileDmzCallback {
    void onAnalysisComplete(in DmzAnalysisResult result);
    void onProgress(String stage, int progressPercent);
    void onError(int errorCode, String message);
}
