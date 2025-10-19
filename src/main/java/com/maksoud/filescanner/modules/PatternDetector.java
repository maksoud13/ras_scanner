package com.maksoud.filescanner.modules;

import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;

public class PatternDetector {
    private static final List<String> MALICIOUS_PATTERNS = Arrays.asList(
            "system32", "sysnative", "windows\\\\system",
            "regsvr32", "rundll32", "schtasks", "wmic",
            "powershell.*-window.*hidden", "cmd.*/c",
            "format.*/q", "del.*/f", "rmdir.*/s",
            "net.*user", "net.*localgroup",
            "sc.*create", "sc.*start",
            "taskkill.*/f", "tskill",
            "attrib.*-r.*-s.*-h",
            "copy.*system32", "xcopy.*system32",
            "bcdedit", "bootcfg",
            "fsutil", "diskpart",
            "vssadmin.*delete.*shadows",
            "wbadmin.*delete",
            "certutil.*-decode", "certutil.*-urlcache");

    private List<Pattern> compiledPatterns;

    public PatternDetector() {
        this.compiledPatterns = new ArrayList<>();
        for (String pattern : MALICIOUS_PATTERNS) {
            compiledPatterns.add(Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
        }
    }

    public int detectPatterns(File file, FileAnalysisResult result) {
        if (!isTextFile(file)) {
            return 0;
        }

        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            List<String> detectedPatterns = new ArrayList<>();

            for (Pattern pattern : compiledPatterns) {
                if (pattern.matcher(content).find()) {
                    detectedPatterns.add(pattern.pattern());
                }
            }

            if (!detectedPatterns.isEmpty()) {
                result.addAnalysisDetail("Detected Patterns", detectedPatterns);
                result.addWarning("Malicious patterns detected: " +
                        String.join(", ", detectedPatterns));
                return detectedPatterns.size() * 10;
            }

        } catch (IOException e) {
            result.addWarning("Error reading file for pattern detection: " + e.getMessage());
        }

        return 0;
    }

    private boolean isTextFile(File file) {
        String name = file.getName().toLowerCase();
        return name.endsWith(".bat") || name.endsWith(".cmd") ||
                name.endsWith(".ps1") || name.endsWith(".vbs") ||
                name.endsWith(".js") || name.endsWith(".txt");
    }
}
