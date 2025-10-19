package com.maksoud.filescanner.analyzer.model;
import java.util.Date;
import java.util.Map;

public class AnalysisResponse {
    private boolean success;
    private String message;
    private Date timestamp;
    private ScanResult scanResult;
    private Map<String, Object> details;
    
    // Constructors
    public AnalysisResponse() {
        this.timestamp = new Date();
    }
    
    public AnalysisResponse(boolean success, String message) {
        this();
        this.success = success;
        this.message = message;
    }
    
    public AnalysisResponse(boolean success, String message, ScanResult scanResult) {
        this(success, message);
        this.scanResult = scanResult;
    }
    
    // Getters and Setters
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public Date getTimestamp() { return timestamp; }
    public void setTimestamp(Date timestamp) { this.timestamp = timestamp; }
    
    public ScanResult getScanResult() { return scanResult; }
    public void setScanResult(ScanResult scanResult) { this.scanResult = scanResult; }
    
    public Map<String, Object> getDetails() { return details; }
    public void setDetails(Map<String, Object> details) { this.details = details; }
}