package com.maksoud.filescanner.modules;

import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Date;

public class BehaviorAnalyzer {
    
    public int analyzeBehavior(File file, FileAnalysisResult result) {
        int riskScore = 0;
        
        try {
            Path path = file.toPath();
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
            
            // Check file attributes
            riskScore += checkFileAttributes(file, result);
            
            // Check file location
            riskScore += checkFileLocation(file, result);
            
            // Check timestamp anomalies
            riskScore += checkTimestamps(attrs, result);
            
        } catch (Exception e) {
            result.addWarning("Error analyzing file behavior: " + e.getMessage());
        }
        
        return riskScore;
    }
    
    private int checkFileAttributes(File file, FileAnalysisResult result) {
        int risk = 0;
        
        if (file.isHidden()) {
            result.addWarning("File is hidden");
            risk += 5;
        }
        
        // Check for double extensions
        String name = file.getName().toLowerCase();
        if (name.matches(".*\\.[a-z]{3}\\.[a-z]{3}$")) {
            result.addWarning("Double file extension detected");
            risk += 15;
        }
        
        // Check for spaces in filename (obfuscation technique)
        if (name.contains(" ")) {
            result.addWarning("Suspicious spaces in filename");
            risk += 5;
        }
        
        return risk;
    }
    
    private int checkFileLocation(File file, FileAnalysisResult result) {
        String path = file.getAbsolutePath().toLowerCase();
        
        // Check for files in temp directories
        if (path.contains("temp") || path.contains("tmp")) {
            result.addWarning("File located in temporary directory");
            return 10;
        }
        
        // Check for files in startup locations
        if (path.contains("startup") || path.contains("autostart")) {
            result.addWarning("File located in startup directory");
            return 20;
        }
        
        return 0;
    }
    
    private int checkTimestamps(BasicFileAttributes attrs, FileAnalysisResult result) {
        long created = attrs.creationTime().toMillis();
        long modified = attrs.lastModifiedTime().toMillis();
        long accessed = attrs.lastAccessTime().toMillis();
        
        result.addAnalysisDetail("Created", new Date(created));
        result.addAnalysisDetail("Modified", new Date(modified));
        result.addAnalysisDetail("Accessed", new Date(accessed));
        
        // Check if modified time is before created time (impossible)
        if (modified < created) {
            result.addWarning("Suspicious timestamps: modified before creation");
            return 15;
        }
        
        return 0;
    }
}