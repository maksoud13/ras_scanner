package com.maksoud.filescanner.core;

import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;
import com.maksoud.filescanner.analyzer.model.ScanConfig;
import com.maksoud.filescanner.analyzer.model.SecurityRisk;
import com.maksoud.filescanner.modules.*;
import com.maksoud.filescanner.modules.ransomware.RansomwareDetector;
import com.maksoud.filescanner.modules.ransomware.BehaviorMonitor;

import java.io.File;
import java.util.*;

public class SecurityScanner {
    private ScanConfig config;
    private SignatureAnalyzer signatureAnalyzer;
    private EntropyCalculator entropyCalculator;
    private PatternDetector patternDetector;
    private BehaviorAnalyzer behaviorAnalyzer;
    private RansomwareDetector ransomwareDetector;
    private BehaviorMonitor behaviorMonitor;

    public SecurityScanner() {
        this.config = new ScanConfig();
        this.signatureAnalyzer = new SignatureAnalyzer();
        this.entropyCalculator = new EntropyCalculator();
        this.patternDetector = new PatternDetector();
        this.behaviorAnalyzer = new BehaviorAnalyzer();
        this.ransomwareDetector = new RansomwareDetector();
        this.behaviorMonitor = new BehaviorMonitor();
    }

    public SecurityScanner(ScanConfig config) {
        this.config = config;
        this.signatureAnalyzer = new SignatureAnalyzer();
        this.entropyCalculator = new EntropyCalculator();
        this.patternDetector = new PatternDetector();
        this.behaviorAnalyzer = new BehaviorAnalyzer();
        this.ransomwareDetector = new RansomwareDetector();
        this.behaviorMonitor = new BehaviorMonitor();
    }

    public FileAnalysisResult analyzeFile(String filePath) {
        FileAnalysisResult result = new FileAnalysisResult();
        File file = new File(filePath);

        if (!file.exists()) {
            result.addWarning("File does not exist");
            result.setRiskLevel(SecurityRisk.LOW);
            return result;
        }

        result.setFilePath(filePath);
        result.setFileName(file.getName());
        result.setFileSize(file.length());
        result.setFileExtension(getFileExtension(file.getName()));

        try {
            // Perform security analysis
            int riskScore = 0;

            // 1. Check file extension
            riskScore += checkFileExtension(result);

            // 2. Analyze file signature
            riskScore += signatureAnalyzer.analyzeSignature(file, result);

            // 3. Calculate entropy
            riskScore += entropyCalculator.calculateEntropyRisk(file, result);

            // 4. Detect malicious patterns
            riskScore += patternDetector.detectPatterns(file, result);

            // 5. Analyze behavior indicators
            riskScore += behaviorAnalyzer.analyzeBehavior(file, result);

            // 6. Check system directory targeting
            riskScore += checkSystemDirectoryTargeting(result);

            // 7. Ransomware-specific detection (HIGH PRIORITY)
            riskScore += ransomwareDetector.detectRansomware(file, result);

            result.setRiskScore(riskScore);
            determineRiskLevel(result);

        } catch (Exception e) {
            result.addWarning("Error during analysis: " + e.getMessage());
            result.setRiskLevel(SecurityRisk.MEDIUM);
        }

        return result;
    }

    private int checkFileExtension(FileAnalysisResult result) {
        String extension = result.getFileExtension().toLowerCase();
        if (config.getDangerousExtensions().contains(extension)) {
            result.addWarning("Dangerous file extension: " + extension);
            return 20;
        }
        return 0;
    }

    private int checkSystemDirectoryTargeting(FileAnalysisResult result) {
        String filePath = result.getFilePath().toLowerCase();
        for (String sysDir : config.getSystemDirectories()) {
            if (filePath.contains(sysDir)) {
                result.addWarning("File targets system directory: " + sysDir);
                return 30;
            }
        }
        return 0;
    }

    private void determineRiskLevel(FileAnalysisResult result) {
        int score = result.getRiskScore();

        if (score >= 80) {
            result.setRiskLevel(SecurityRisk.CRITICAL);
            result.setSafe(false);
        } else if (score >= 60) {
            result.setRiskLevel(SecurityRisk.HIGH);
            result.setSafe(false);
        } else if (score >= 40) {
            result.setRiskLevel(SecurityRisk.MEDIUM);
            result.setSafe(false);
        } else {
            result.setRiskLevel(SecurityRisk.LOW);
            result.setSafe(true);
        }
    }

    private String getFileExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        return (lastDot == -1) ? "" : filename.substring(lastDot);
    }

    public List<FileAnalysisResult> analyzeDirectory(String directoryPath) {
        List<FileAnalysisResult> results = new ArrayList<>();
        File directory = new File(directoryPath);

        if (!directory.exists() || !directory.isDirectory()) {
            return results;
        }

        scanDirectory(directory, results);
        return results;
    }

    private void scanDirectory(File directory, List<FileAnalysisResult> results) {
        File[] files = directory.listFiles();
        if (files == null)
            return;

        for (File file : files) {
            if (file.isDirectory()) {
                if (config.isDeepScan()) {
                    scanDirectory(file, results);
                }
            } else {
                // Check file size limit
                if (file.length() <= config.getMaxFileSizeMB() * 1024 * 1024) {
                    results.add(analyzeFile(file.getAbsolutePath()));
                }
            }
        }
    }

    // Add new method for ransomware-specific scanning
    public Map<String, Object> performRansomwareScan(String directoryPath) {
        Map<String, Object> scanResults = new HashMap<>();

        // Use the ransomware detector for specialized scanning
        Map<String, Object> ransomwareAnalysis = ransomwareDetector.analyzeDirectoryForRansomware(directoryPath);

        // Combine with traditional security scan
        List<FileAnalysisResult> securityResults = analyzeDirectory(directoryPath);

        // Count high-risk files
        long highRiskFiles = securityResults.stream()
                .filter(r -> r.getRiskLevel() == SecurityRisk.HIGH ||
                        r.getRiskLevel() == SecurityRisk.CRITICAL)
                .count();

        scanResults.put("ransomwareAnalysis", ransomwareAnalysis);
        scanResults.put("securityAnalysis", securityResults);
        scanResults.put("highRiskFileCount", highRiskFiles);
        scanResults.put("totalFilesScanned", securityResults.size());

        // Determine overall ransomware risk
        boolean ransomwareDetected = (highRiskFiles > 0) ||
                !((List<?>) ransomwareAnalysis.get("suspiciousFiles")).isEmpty();

        scanResults.put("ransomwareDetected", ransomwareDetected);
        scanResults.put("timestamp", new Date());

        return scanResults;
    }

    // Add real-time monitoring methods
    public void startRealTimeMonitoring(String directoryPath) {
        behaviorMonitor.startMonitoring(directoryPath);
    }

    public void stopRealTimeMonitoring() {
        behaviorMonitor.stopMonitoring();
    }

    public Map<String, Object> getMonitoringStatus() {
        return behaviorMonitor.getMonitoringStats();
    }
}