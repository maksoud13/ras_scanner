package com.maksoud.filescanner.modules.ransomware;

import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;
import com.maksoud.filescanner.modules.EntropyCalculator;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RansomwareDetector {
    private EntropyCalculator entropyCalculator;

    public RansomwareDetector() {
        this.entropyCalculator = new EntropyCalculator();
    }

    public int detectRansomware(File file, FileAnalysisResult result) {
        int riskScore = 0;

        try {
            // 1. Check for ransomware file extensions
            riskScore += checkRansomwareExtensions(file, result);

            // 2. Check file content for ransomware patterns
            riskScore += checkRansomwareContent(file, result);

            // 3. Check for encryption indicators
            riskScore += checkEncryptionIndicators(file, result);

            // 4. Check file behavior patterns
            riskScore += checkRansomwareBehavior(file, result);

            // 5. Check for mass file operations
            riskScore += checkMassOperationIndicators(file, result);

        } catch (Exception e) {
            result.addWarning("Error in ransomware detection: " + e.getMessage());
        }

        return riskScore;
    }

    private int checkRansomwareExtensions(File file, FileAnalysisResult result) {
        String extension = getFileExtension(file.getName()).toLowerCase();

        if (RansomwarePatterns.RANSOMWARE_EXTENSIONS.contains(extension)) {
            result.addWarning("KNOWN RANSOMWARE EXTENSION: " + extension);
            result.addAnalysisDetail("Ransomware Extension Match", extension);
            return 50; // High risk for known ransomware extensions
        }

        // Check for double extensions (common in ransomware)
        if (file.getName().matches(".*\\.[a-z]{3,4}\\.[a-z]{3,8}$")) {
            result.addWarning("Suspicious double file extension");
            result.addAnalysisDetail("Double Extension", file.getName());
            return 20;
        }

        return 0;
    }

    private int checkRansomwareContent(File file, FileAnalysisResult result) {
        if (!isReadableTextFile(file)) {
            return 0;
        }

        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            List<String> detectedPatterns = new ArrayList<>();

            // Check for ransomware content patterns
            for (Pattern pattern : RansomwarePatterns.RANSOMWARE_CONTENT_PATTERNS) {
                Matcher matcher = pattern.matcher(content);
                if (matcher.find()) {
                    detectedPatterns.add(pattern.pattern());
                }
            }

            if (!detectedPatterns.isEmpty()) {
                result.addWarning("RANSOMWARE CONTENT DETECTED: " +
                        String.join(", ", detectedPatterns));
                result.addAnalysisDetail("Ransomware Content Patterns", detectedPatterns);
                return 40;
            }

        } catch (IOException e) {
            // Skip files that can't be read
        }

        return 0;
    }

    private int checkEncryptionIndicators(File file, FileAnalysisResult result) {
        try {
            // High entropy is a strong indicator of encryption
            double entropy = entropyCalculator.calculateEntropy(file);
            result.addAnalysisDetail("File Entropy", String.format("%.2f", entropy));

            if (entropy > 7.8) {
                result.addWarning("VERY HIGH ENTROPY: " + String.format("%.2f", entropy) +
                        " (possible encryption)");

                // Additional encryption checks
                if (isLikelyEncrypted(file)) {
                    result.addWarning("STRONG ENCRYPTION INDICATORS DETECTED");
                    return 60;
                }
                return 30;
            }

        } catch (IOException e) {
            result.addWarning("Error checking encryption indicators: " + e.getMessage());
        }

        return 0;
    }

    private int checkRansomwareBehavior(File file, FileAnalysisResult result) {
        if (!isReadableTextFile(file)) {
            return 0;
        }

        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            List<String> detectedBehaviors = new ArrayList<>();

            // Check for ransomware behavioral patterns
            for (Pattern pattern : RansomwarePatterns.RANSOMWARE_BEHAVIOR_PATTERNS) {
                Matcher matcher = pattern.matcher(content);
                if (matcher.find()) {
                    detectedBehaviors.add(pattern.pattern());
                }
            }

            if (!detectedBehaviors.isEmpty()) {
                result.addWarning("RANSOMWARE BEHAVIOR DETECTED: " +
                        String.join(", ", detectedBehaviors));
                result.addAnalysisDetail("Ransomware Behavior Patterns", detectedBehaviors);
                return 45;
            }

        } catch (IOException e) {
            // Skip files that can't be read
        }

        return 0;
    }

    private int checkMassOperationIndicators(File file, FileAnalysisResult result) {
        if (!isReadableTextFile(file)) {
            return 0;
        }

        try {
            String content = new String(Files.readAllBytes(file.toPath()));

            // Check for mass file operations
            int massOperationScore = 0;

            // Multiple file extensions in commands
            if (content.matches("(?s).*\\.(doc|docx|pdf|jpg|jpeg|png|xls|xlsx).*")) {
                massOperationScore += 10;
            }

            // Recursive directory operations
            if (content.matches("(?s).*\\b(dir|ls|find)\\b.*/.*[Ss].*")) {
                massOperationScore += 15;
            }

            // Batch file operations
            if (content.matches("(?s).*\\b(for|while)\\b.*\\b(in|do)\\b.*")) {
                massOperationScore += 10;
            }

            if (massOperationScore >= 20) {
                result.addWarning("MASS FILE OPERATION PATTERNS DETECTED");
                return 25;
            }

        } catch (IOException e) {
            // Skip files that can't be read
        }

        return 0;
    }

    private boolean isLikelyEncrypted(File file) throws IOException {
        // Additional checks for encrypted files
        byte[] content = Files.readAllBytes(file.toPath());

        // Check file size (encrypted files often have specific sizes)
        if (file.length() % 16 == 0 || file.length() % 32 == 0) {
            return true; // Common encryption block sizes
        }

        // Check for lack of recognizable file headers
        if (content.length >= 4) {
            String header = String.format("%02X%02X%02X%02X",
                    content[0] & 0xFF, content[1] & 0xFF,
                    content[2] & 0xFF, content[3] & 0xFF);

            // Common file headers to check against
            Set<String> commonHeaders = Set.of(
                    "25504446", // PDF
                    "504B0304", // ZIP
                    "89504E47", // PNG
                    "FFD8FFE0", // JPEG
                    "D0CF11E0", // MS Office
                    "4D5A9000" // EXE
            );

            // If no common header and high entropy, likely encrypted
            return !commonHeaders.contains(header);
        }

        return false;
    }

    private boolean isReadableTextFile(File file) {
        String name = file.getName().toLowerCase();
        return name.endsWith(".bat") || name.endsWith(".cmd") ||
                name.endsWith(".ps1") || name.endsWith(".vbs") ||
                name.endsWith(".js") || name.endsWith(".txt") ||
                name.endsWith(".log");
    }

    private String getFileExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        return (lastDot == -1) ? "" : filename.substring(lastDot);
    }

    // Method to analyze directory for ransomware patterns
    public Map<String, Object> analyzeDirectoryForRansomware(String directoryPath) {
        Map<String, Object> analysis = new HashMap<>();
        List<File> suspiciousFiles = new ArrayList<>();
        int encryptedFileCount = 0;
        int ransomNoteCount = 0;

        File directory = new File(directoryPath);
        if (!directory.exists() || !directory.isDirectory()) {
            return analysis;
        }

        scanDirectoryForRansomware(directory, suspiciousFiles, analysis);

        analysis.put("suspiciousFiles", suspiciousFiles);
        analysis.put("suspiciousFileCount", suspiciousFiles.size());
        analysis.put("directoryScanned", directoryPath);

        return analysis;
    }

    private void scanDirectoryForRansomware(File directory, List<File> suspiciousFiles,
            Map<String, Object> analysis) {
        File[] files = directory.listFiles();
        if (files == null)
            return;

        for (File file : files) {
            if (file.isDirectory()) {
                scanDirectoryForRansomware(file, suspiciousFiles, analysis);
            } else {
                // Check for ransom notes
                if (isRansomNote(file)) {
                    suspiciousFiles.add(file);
                    analysis.put("ransomNoteFound", true);
                }

                // Check for encrypted files
                if (hasRansomwareExtension(file)) {
                    suspiciousFiles.add(file);
                }
            }
        }
    }

    private boolean isRansomNote(File file) {
        String name = file.getName().toLowerCase();
        return name.contains("readme") || name.contains("decrypt") ||
                name.contains("recover") || name.contains("ransom") ||
                name.contains("how_to") || name.contains("help_restore");
    }

    private boolean hasRansomwareExtension(File file) {
        String extension = getFileExtension(file.getName()).toLowerCase();
        return RansomwarePatterns.RANSOMWARE_EXTENSIONS.contains(extension);
    }
}