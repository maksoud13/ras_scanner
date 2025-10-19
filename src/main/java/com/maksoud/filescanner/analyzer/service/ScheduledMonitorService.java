package com.maksoud.filescanner.analyzer.service;

import com.maksoud.filescanner.core.SecurityScanner;
import com.maksoud.filescanner.analyzer.model.ScanResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ScheduledMonitorService {

    @Autowired
    private SecurityScanner securityScanner;

    @Autowired
    private RansomwareDetectionService ransomwareService;

    private final Map<String, Long> lastScanTimes = new ConcurrentHashMap<>();
    private final Set<String> monitoredPaths = ConcurrentHashMap.newKeySet();
    private final List<String> alertLog = Collections.synchronizedList(new ArrayList<>());

    // Critical system paths to monitor
    private final List<String> CRITICAL_PATHS = Arrays.asList(
            "C:\\Windows\\System32",
            "C:\\Program Files",
            "C:\\ProgramData",
            "C:\\Users",
            System.getProperty("user.home") + "\\Documents");

    /**
     * Scan critical system paths every 5 minutes
     */
    @Scheduled(fixedRate = 300000) // 5 minutes
    public void scheduledSystemScan() {
        log("Starting scheduled system scan...");

        for (String path : CRITICAL_PATHS) {
            if (new File(path).exists()) {
                try {
                    ScanResult result = ransomwareService.performRansomwareScan(path);

                    if (result.isRansomwareDetected()) {
                        String alert = String.format(
                                "🚨 RANSOMWARE DETECTED in %s at %s - %d suspicious files found",
                                path, new Date(), result.getSuspiciousFiles());
                        logAlert(alert);
                        triggerEmergencyProtocol(path, result);
                    } else if (result.getSuspiciousFiles() > 0) {
                        log(String.format("Suspicious activity in %s: %d files",
                                path, result.getSuspiciousFiles()));
                    }

                } catch (Exception e) {
                    log("Error scanning path " + path + ": " + e.getMessage());
                }
            }
        }
        log("Scheduled system scan completed");
    }

    /**
     * Quick USB monitoring every 30 seconds
     */
    @Scheduled(fixedRate = 30000) // 30 seconds
    public void checkRemovableDrives() {
        File[] roots = File.listRoots();
        for (File root : roots) {
            if (isRemovableDrive(root)) {
                String path = root.getAbsolutePath();
                if (!monitoredPaths.contains(path)) {
                    log("New removable drive detected: " + path);
                    monitoredPaths.add(path);
                    scanRemovableDrive(path);
                }
            }
        }
    }

    /**
     * Memory and performance monitoring every minute
     */
    @Scheduled(fixedRate = 60000) // 1 minute
    public void systemHealthCheck() {
        Runtime runtime = Runtime.getRuntime();
        long usedMemory = (runtime.totalMemory() - runtime.freeMemory()) / 1024 / 1024;
        long maxMemory = runtime.maxMemory() / 1024 / 1024;

        if (usedMemory > maxMemory * 0.8) {
            logAlert("High memory usage: " + usedMemory + "MB/" + maxMemory + "MB");
        }

        // Check for suspicious processes (simplified)
        checkSuspiciousProcesses();
    }

    /**
     * Deep scan during system idle time (2 AM daily)
     */
    @Scheduled(cron = "0 0 2 * * ?") // 2 AM daily
    public void dailyDeepScan() {
        log("Starting daily deep security scan...");
        for (String path : CRITICAL_PATHS) {
            if (new File(path).exists()) {
                try {
                    ScanResult result = (ScanResult) securityScanner.analyzeDirectory(path);
                    log(String.format("Daily scan %s: %d files, %d suspicious",
                            path, result.getTotalFilesScanned(), result.getSuspiciousFiles()));
                } catch (Exception e) {
                    log("Error in daily scan of " + path + ": " + e.getMessage());
                }
            }
        }
    }

    private boolean isRemovableDrive(File root) {
        String path = root.getAbsolutePath().toLowerCase();
        // Simple heuristic for removable drives
        return path.startsWith("d:") || path.startsWith("e:") || path.startsWith("f:") ||
                path.startsWith("g:") || path.startsWith("h:");
    }

    private void scanRemovableDrive(String drivePath) {
        try {
            ScanResult result = ransomwareService.performRansomwareScan(drivePath);
            if (result.isRansomwareDetected() || result.getSuspiciousFiles() > 0) {
                String alert = String.format(
                        "Suspicious content on removable drive %s: %d files",
                        drivePath, result.getSuspiciousFiles());
                logAlert(alert);
            }
        } catch (Exception e) {
            log("Error scanning removable drive " + drivePath + ": " + e.getMessage());
        }
    }

    private void checkSuspiciousProcesses() {
        // This would require JNA or executing system commands
        // For now, we'll monitor our own application health
        try {
            // Check if critical files are accessible
            File system32 = new File("C:\\Windows\\System32");
            if (!system32.canRead()) {
                logAlert("CRITICAL: Cannot access System32 directory!");
            }
        } catch (Exception e) {
            log("Error checking system health: " + e.getMessage());
        }
    }

    private void triggerEmergencyProtocol(String infectedPath, ScanResult result) {
        logAlert("EMERGENCY PROTOCOL ACTIVATED FOR: " + infectedPath);

        // In a real implementation, you would:
        // 1. Quarantine suspicious files
        // 2. Send emergency alerts
        // 3. Possibly disconnect from network
        // 4. Create system restore point

        // Example: Log emergency actions
        log("Emergency actions triggered for " + infectedPath);
        log("Suspicious files count: " + result.getSuspiciousFiles());
        log("Critical files count: " + result.getCriticalFiles());
    }

    private void log(String message) {
        String logEntry = String.format("[%s] %s", new Date(), message);
        System.out.println(logEntry);
        alertLog.add("INFO: " + logEntry);

        // Keep only last 1000 entries
        if (alertLog.size() > 1000) {
            alertLog.remove(0);
        }
    }

    private void logAlert(String message) {
        String alertEntry = String.format("[%s] 🚨 ALERT: %s", new Date(), message);
        System.err.println(alertEntry);
        alertLog.add("ALERT: " + alertEntry);
    }

    public List<String> getAlertLog() {
        return new ArrayList<>(alertLog);
    }

    public Map<String, Long> getLastScanTimes() {
        return new HashMap<>(lastScanTimes);
    }
}
