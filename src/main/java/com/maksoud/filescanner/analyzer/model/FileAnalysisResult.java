package com.maksoud.filescanner.analyzer.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class FileAnalysisResult {
    private String filePath;
    private String fileName;
    private long fileSize;
    private String fileExtension;
    private SecurityRisk riskLevel;
    private int riskScore;
    private List<String> warnings;
    private Map<String, Object> analysisDetails;
    private boolean isSafe;
    
    public FileAnalysisResult() {
        this.warnings = new ArrayList<>();
        this.analysisDetails = new HashMap<>();
        this.riskLevel = SecurityRisk.LOW;
    }
    
    // Getters and Setters
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    
    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }
    
    public String getFileExtension() { return fileExtension; }
    public void setFileExtension(String fileExtension) { this.fileExtension = fileExtension; }
    
    public SecurityRisk getRiskLevel() { return riskLevel; }
    public void setRiskLevel(SecurityRisk riskLevel) { this.riskLevel = riskLevel; }
    
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    
    public List<String> getWarnings() { return warnings; }
    public void addWarning(String warning) { this.warnings.add(warning); }
    
    public Map<String, Object> getAnalysisDetails() { return analysisDetails; }
    public void addAnalysisDetail(String key, Object value) { 
        this.analysisDetails.put(key, value); 
    }
    
    public boolean isSafe() { return isSafe; }
    public void setSafe(boolean safe) { isSafe = safe; }
    
    @Override
    public String toString() {
        return "FileAnalysisResult{" +
                "fileName='" + fileName + '\'' +
                ", riskLevel=" + riskLevel +
                ", riskScore=" + riskScore +
                ", isSafe=" + isSafe +
                ", warnings=" + warnings.size() +
                '}';
    }
}