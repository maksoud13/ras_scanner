package com.maksoud.filescanner.analyzer.model;

import java.util.List;
import java.util.Map;

public class ScanResult {
    private int totalFilesScanned;
    private int safeFiles;
    private int suspiciousFiles;
    private int criticalFiles;
    private List<FileAnalysisResult> fileResults;
    private Map<String, Object> ransomwareAnalysis;
    private long scanDurationMs;
    private String scanPath;

    // Constructors
    public ScanResult() {
    }

    public ScanResult(String scanPath) {
        this.scanPath = scanPath;
    }

    // Getters and Setters
    public int getTotalFilesScanned() {
        return totalFilesScanned;
    }

    public void setTotalFilesScanned(int totalFilesScanned) {
        this.totalFilesScanned = totalFilesScanned;
    }

    public int getSafeFiles() {
        return safeFiles;
    }

    public void setSafeFiles(int safeFiles) {
        this.safeFiles = safeFiles;
    }

    public int getSuspiciousFiles() {
        return suspiciousFiles;
    }

    public void setSuspiciousFiles(int suspiciousFiles) {
        this.suspiciousFiles = suspiciousFiles;
    }

    public int getCriticalFiles() {
        return criticalFiles;
    }

    public void setCriticalFiles(int criticalFiles) {
        this.criticalFiles = criticalFiles;
    }

    public List<FileAnalysisResult> getFileResults() {
        return fileResults;
    }

    public void setFileResults(List<FileAnalysisResult> fileResults) {
        this.fileResults = fileResults;
    }

    public Map<String, Object> getRansomwareAnalysis() {
        return ransomwareAnalysis;
    }

    public void setRansomwareAnalysis(Map<String, Object> ransomwareAnalysis) {
        this.ransomwareAnalysis = ransomwareAnalysis;
    }

    public long getScanDurationMs() {
        return scanDurationMs;
    }

    public void setScanDurationMs(long scanDurationMs) {
        this.scanDurationMs = scanDurationMs;
    }

    public String getScanPath() {
        return scanPath;
    }

    public void setScanPath(String scanPath) {
        this.scanPath = scanPath;
    }

    // Helper methods
    public boolean isRansomwareDetected() {
        return ransomwareAnalysis != null &&
                ransomwareAnalysis.containsKey("ransomwareDetected") &&
                (Boolean) ransomwareAnalysis.get("ransomwareDetected");
    }

    public double getRiskPercentage() {
        if (totalFilesScanned == 0)
            return 0.0;
        return (suspiciousFiles + criticalFiles) * 100.0 / totalFilesScanned;
    }
}