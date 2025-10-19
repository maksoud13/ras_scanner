package com.maksoud.filescanner.analyzer.model;

import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;

public class ScanConfig {
    private Set<String> dangerousExtensions;
    private Set<String> systemDirectories;
    private Set<String> excludedDirectories;
    private double entropyThreshold;
    private int maxFileSizeMB;
    private boolean deepScan;
    private boolean monitorUsb;
    private boolean enableRansomwareDetection;
    private boolean enableRealTimeMonitoring;
    private int maxScanDepth;
    private int threadPoolSize;
    
    public ScanConfig() {
        // Default dangerous extensions
        this.dangerousExtensions = new HashSet<>(Arrays.asList(
            ".bat", ".cmd", ".ps1", ".vbs", ".js", ".exe", ".scr", 
            ".pif", ".com", ".jar", ".dll", ".ddl", ".sys", ".msi",
            ".reg", ".inf", ".tmp", ".dat", ".bin"
        ));
        
        // System directories to monitor
        this.systemDirectories = new HashSet<>(Arrays.asList(
            "system32", "syswow64", "windows\\system", "program files",
            "programdata", "users", "appdata", "windows\\temp"
        ));
        
        // Directories to exclude from scanning
        this.excludedDirectories = new HashSet<>(Arrays.asList(
            "windows\\system32\\config", "windows\\system32\\logfiles",
            "windows\\logs", "programdata\\microsoft"
        ));
        
        this.entropyThreshold = 7.5;
        this.maxFileSizeMB = 100;
        this.deepScan = true;
        this.monitorUsb = true;
        this.enableRansomwareDetection = true;
        this.enableRealTimeMonitoring = false;
        this.maxScanDepth = 10;
        this.threadPoolSize = 4;
    }
    
    // Getters and Setters
    public Set<String> getDangerousExtensions() { return dangerousExtensions; }
    public void setDangerousExtensions(Set<String> dangerousExtensions) { 
        this.dangerousExtensions = dangerousExtensions; 
    }
    
    public Set<String> getSystemDirectories() { return systemDirectories; }
    public void setSystemDirectories(Set<String> systemDirectories) { 
        this.systemDirectories = systemDirectories; 
    }
    
    public Set<String> getExcludedDirectories() { return excludedDirectories; }
    public void setExcludedDirectories(Set<String> excludedDirectories) { 
        this.excludedDirectories = excludedDirectories; 
    }
    
    public double getEntropyThreshold() { return entropyThreshold; }
    public void setEntropyThreshold(double entropyThreshold) { 
        this.entropyThreshold = entropyThreshold; 
    }
    
    public int getMaxFileSizeMB() { return maxFileSizeMB; }
    public void setMaxFileSizeMB(int maxFileSizeMB) { 
        this.maxFileSizeMB = maxFileSizeMB; 
    }
    
    public boolean isDeepScan() { return deepScan; }
    public void setDeepScan(boolean deepScan) { this.deepScan = deepScan; }
    
    public boolean isMonitorUsb() { return monitorUsb; }
    public void setMonitorUsb(boolean monitorUsb) { this.monitorUsb = monitorUsb; }
    
    public boolean isEnableRansomwareDetection() { return enableRansomwareDetection; }
    public void setEnableRansomwareDetection(boolean enableRansomwareDetection) { 
        this.enableRansomwareDetection = enableRansomwareDetection; 
    }
    
    public boolean isEnableRealTimeMonitoring() { return enableRealTimeMonitoring; }
    public void setEnableRealTimeMonitoring(boolean enableRealTimeMonitoring) { 
        this.enableRealTimeMonitoring = enableRealTimeMonitoring; 
    }
    
    public int getMaxScanDepth() { return maxScanDepth; }
    public void setMaxScanDepth(int maxScanDepth) { 
        this.maxScanDepth = maxScanDepth; 
    }
    
    public int getThreadPoolSize() { return threadPoolSize; }
    public void setThreadPoolSize(int threadPoolSize) { 
        this.threadPoolSize = threadPoolSize; 
    }
    
    // Helper methods
    public void addDangerousExtension(String extension) {
        this.dangerousExtensions.add(extension.toLowerCase());
    }
    
    public void removeDangerousExtension(String extension) {
        this.dangerousExtensions.remove(extension.toLowerCase());
    }
    
    public void addSystemDirectory(String directory) {
        this.systemDirectories.add(directory.toLowerCase());
    }
    
    public void addExcludedDirectory(String directory) {
        this.excludedDirectories.add(directory.toLowerCase());
    }
    
    public boolean isExcludedDirectory(String path) {
        String lowerPath = path.toLowerCase();
        return excludedDirectories.stream().anyMatch(lowerPath::contains);
    }
    
    public boolean isSystemDirectory(String path) {
        String lowerPath = path.toLowerCase();
        return systemDirectories.stream().anyMatch(lowerPath::contains);
    }
    
    public boolean isDangerousExtension(String extension) {
        return dangerousExtensions.contains(extension.toLowerCase());
    }
}
