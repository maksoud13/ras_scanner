package com.maksoud.filescanner.analyzer.config;

import jakarta.validation.constraints.NotBlank;

public class AnalysisRequest {

    @NotBlank(message = "File path is required")
    private String filePath;

    private boolean deepScan = true;
    private boolean includeRansomwareCheck = true;
    private int maxFileSizeMB = 100;

    // Constructors
    public AnalysisRequest() {
    }

    public AnalysisRequest(String filePath) {
        this.filePath = filePath;
    }

    // Getters and Setters
    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public boolean isDeepScan() {
        return deepScan;
    }

    public void setDeepScan(boolean deepScan) {
        this.deepScan = deepScan;
    }

    public boolean isIncludeRansomwareCheck() {
        return includeRansomwareCheck;
    }

    public void setIncludeRansomwareCheck(boolean includeRansomwareCheck) {
        this.includeRansomwareCheck = includeRansomwareCheck;
    }

    public int getMaxFileSizeMB() {
        return maxFileSizeMB;
    }

    public void setMaxFileSizeMB(int maxFileSizeMB) {
        this.maxFileSizeMB = maxFileSizeMB;
    }
}