package com.maksoud.filescanner.analyzer.service;

import com.maksoud.filescanner.core.SecurityScanner;
import com.maksoud.filescanner.analyzer.model.ScanResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class RansomwareDetectionService {

    @Autowired
    private SecurityScanner securityScanner;

    public ScanResult performRansomwareScan(String directoryPath) {
        long startTime = System.currentTimeMillis();

        Map<String, Object> ransomwareAnalysis = securityScanner.performRansomwareScan(directoryPath);

        @SuppressWarnings("unchecked")
        List<com.maksoud.filescanner.analyzer.model.FileAnalysisResult> securityResults = (List<com.maksoud.filescanner.analyzer.model.FileAnalysisResult>) ransomwareAnalysis
                .get("securityAnalysis");

        ScanResult scanResult = new ScanResult(directoryPath);
        scanResult.setFileResults(securityResults);
        scanResult.setRansomwareAnalysis(ransomwareAnalysis);
        scanResult.setTotalFilesScanned(securityResults.size());

        // Calculate ransomware-specific statistics
        boolean ransomwareDetected = (Boolean) ransomwareAnalysis.get("ransomwareDetected");
        int suspiciousFileCount = ((List<?>) ransomwareAnalysis.get("suspiciousFiles")).size();

        scanResult.setSuspiciousFiles(suspiciousFileCount);
        scanResult.setCriticalFiles(ransomwareDetected ? 1 : 0);
        scanResult.setSafeFiles(securityResults.size() - suspiciousFileCount);
        scanResult.setScanDurationMs(System.currentTimeMillis() - startTime);

        return scanResult;
    }

    public void startRealTimeMonitoring(String directoryPath) {
        securityScanner.startRealTimeMonitoring(directoryPath);
    }

    public void stopRealTimeMonitoring() {
        // Implementation to stop monitoring
    }

    public Map<String, Object> getMonitoringStatus() {
        return securityScanner.getMonitoringStatus();
    }
}