package com.maksoud.filescanner.modules;

import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class SignatureAnalyzer {
    private static final Map<String, String> FILE_SIGNATURES = new HashMap<>();

    static {
        FILE_SIGNATURES.put("4D5A", "EXE"); // MZ header
        FILE_SIGNATURES.put("5A4D", "EXE"); // ZM (alternative)
        FILE_SIGNATURES.put("2321", "Script"); // Shebang
        FILE_SIGNATURES.put("FFFE", "Unicode Text");
        FILE_SIGNATURES.put("EFBBBF", "UTF-8 BOM");
        FILE_SIGNATURES.put("D0CF11E0A1B11AE1", "MS Compound File");
        FILE_SIGNATURES.put("504B0304", "ZIP/Java JAR");
        FILE_SIGNATURES.put("526172211A0700", "RAR Archive");
    }

    public int analyzeSignature(File file, FileAnalysisResult result) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] header = new byte[8];
            int bytesRead = fis.read(header);

            if (bytesRead < 2) {
                return 0;
            }

            String hexSignature = bytesToHex(header, bytesRead);
            String detectedType = detectFileType(hexSignature);
            String extension = getFileExtension(file.getName());

            result.addAnalysisDetail("File Signature", hexSignature);
            result.addAnalysisDetail("Detected Type", detectedType);

            // Check for mismatch between extension and actual type
            if (isExtensionMismatch(extension, detectedType)) {
                result.addWarning("File extension mismatch: " + extension + " vs " + detectedType);
                return 25;
            }

        } catch (IOException e) {
            result.addWarning("Error reading file signature: " + e.getMessage());
        }

        return 0;
    }

    private String detectFileType(String hexSignature) {
        for (Map.Entry<String, String> entry : FILE_SIGNATURES.entrySet()) {
            if (hexSignature.startsWith(entry.getKey())) {
                return entry.getValue();
            }
        }
        return "Unknown";
    }

    private boolean isExtensionMismatch(String extension, String detectedType) {
        Map<String, String> extensionMap = Map.of(
                ".exe", "EXE",
                ".zip", "ZIP",
                ".jar", "ZIP",
                ".rar", "RAR");

        String expectedType = extensionMap.get(extension.toLowerCase());
        return expectedType != null && !expectedType.equals(detectedType);
    }

    private String bytesToHex(byte[] bytes, int length) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < length; i++) {
            hex.append(String.format("%02X", bytes[i]));
        }
        return hex.toString();
    }

    private String getFileExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        return (lastDot == -1) ? "" : filename.substring(lastDot);
    }
}