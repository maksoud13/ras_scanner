package com.maksoud.filescanner.analyzer.service;

import com.maksoud.filescanner.core.SecurityScanner;
import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;
import com.maksoud.filescanner.analyzer.model.ScanResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Service
public class SecurityAnalysisService {

    @Autowired
    private SecurityScanner securityScanner;

    public FileAnalysisResult analyzeFile(String filePath) {
        return securityScanner.analyzeFile(filePath);
    }

    public ScanResult analyzeDirectory(String directoryPath) {
        long startTime = System.currentTimeMillis();
        
        List<FileAnalysisResult> fileResults = securityScanner.analyzeDirectory(directoryPath);
        
        ScanResult scanResult = new ScanResult(directoryPath);
        scanResult.setFileResults(fileResults);
        scanResult.setTotalFilesScanned(fileResults.size());
        
        // Calculate statistics
        long safeFiles = fileResults.stream().filter(FileAnalysisResult::isSafe).count();
        long suspiciousFiles = fileResults.stream()
            .filter(r -> !r.isSafe() && r.getRiskLevel().getLevel() < 3)
            .count();
        long criticalFiles = fileResults.stream()
            .filter(r -> r.getRiskLevel().getLevel() >= 3)
            .count();
        
        scanResult.setSafeFiles((int) safeFiles);
        scanResult.setSuspiciousFiles((int) suspiciousFiles);
        scanResult.setCriticalFiles((int) criticalFiles);
        scanResult.setScanDurationMs(System.currentTimeMillis() - startTime);
        
        return scanResult;
    }

    @Async
    public CompletableFuture<ScanResult> analyzeDirectoryAsync(String directoryPath) {
        return CompletableFuture.completedFuture(analyzeDirectory(directoryPath));
    }

    public boolean validatePath(String path) {
        File file = new File(path);
        return file.exists();
    }

    public String getPathType(String path) {
        File file = new File(path);
        if (!file.exists()) {
            return "NOT_EXISTS";
        }
        return file.isDirectory() ? "DIRECTORY" : "FILE";
    }
}