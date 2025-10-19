package com.maksoud.filescanner.modules;

import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class EntropyCalculator {
    
    public int calculateEntropyRisk(File file, FileAnalysisResult result) {
        try {
            double entropy = calculateEntropy(file);
            result.addAnalysisDetail("Entropy", String.format("%.2f", entropy));
            
            if (entropy > 7.5) {
                result.addWarning("High entropy detected: " + String.format("%.2f", entropy) + 
                                " (possible encryption/packing)");
                return 15;
            } else if (entropy > 6.5) {
                result.addWarning("Moderate entropy detected: " + String.format("%.2f", entropy));
                return 5;
            }
            
        } catch (IOException e) {
            result.addWarning("Error calculating entropy: " + e.getMessage());
        }
        
        return 0;
    }
    
    public double calculateEntropy(File file) throws IOException {
        Map<Byte, Integer> frequency = new HashMap<>();
        int totalBytes = 0;
        
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            
            while ((bytesRead = fis.read(buffer)) != -1) {
                totalBytes += bytesRead;
                for (int i = 0; i < bytesRead; i++) {
                    frequency.merge(buffer[i], 1, Integer::sum);
                }
            }
        }
        
        double entropy = 0.0;
        for (int count : frequency.values()) {
            double probability = (double) count / totalBytes;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        
        return entropy;
    }
}
