package com.maksoud.filescanner.modules.ransomware;

import java.io.File;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class BehaviorMonitor {
    private Set<String> monitoredDirectories;
    private Map<String, Long> fileModificationTimes;
    private Map<String, String> fileOriginalExtensions;
    private WatchService watchService;
    private boolean isMonitoring;

    public BehaviorMonitor() {
        this.monitoredDirectories = ConcurrentHashMap.newKeySet();
        this.fileModificationTimes = new ConcurrentHashMap<>();
        this.fileOriginalExtensions = new ConcurrentHashMap<>();
        this.isMonitoring = false;

        try {
            this.watchService = FileSystems.getDefault().newWatchService();
        } catch (Exception e) {
            System.err.println("Error initializing watch service: " + e.getMessage());
        }
    }

    public void startMonitoring(String directoryPath) {
        try {
            Path path = Paths.get(directoryPath);
            if (!Files.exists(path) || !Files.isDirectory(path)) {
                System.err.println("Directory does not exist: " + directoryPath);
                return;
            }

            // Register for file events
            path.register(watchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_DELETE,
                    StandardWatchEventKinds.ENTRY_MODIFY);

            monitoredDirectories.add(directoryPath);
            isMonitoring = true;

            System.out.println("Started monitoring: " + directoryPath);

            // Start monitoring thread
            new Thread(this::monitorEvents).start();

        } catch (Exception e) {
            System.err.println("Error starting monitoring: " + e.getMessage());
        }
    }

    private void monitorEvents() {
        while (isMonitoring) {
            try {
                WatchKey key = watchService.take();

                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();

                    if (kind == StandardWatchEventKinds.OVERFLOW) {
                        continue;
                    }

                    // Get the file name
                    WatchEvent<Path> ev = (WatchEvent<Path>) event;
                    Path filename = ev.context();

                    // Handle the event
                    handleFileEvent(kind, filename, key);
                }

                // Reset the key
                boolean valid = key.reset();
                if (!valid) {
                    break;
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                System.err.println("Error in monitoring: " + e.getMessage());
            }
        }
    }

    private void handleFileEvent(WatchEvent.Kind<?> kind, Path filename, WatchKey key) {
        String filePath = key.watchable() + File.separator + filename;
        File file = new File(filePath);

        if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
            onFileCreated(file);
        } else if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
            onFileModified(file);
        } else if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
            onFileDeleted(file);
        }
    }

    private void onFileCreated(File file) {
        // Store original extension for new files
        String extension = getFileExtension(file.getName());
        fileOriginalExtensions.put(file.getAbsolutePath(), extension);
        fileModificationTimes.put(file.getAbsolutePath(), System.currentTimeMillis());

        // Check for suspicious activity
        checkSuspiciousActivity(file, "CREATED");
    }

    private void onFileModified(File file) {
        long currentTime = System.currentTimeMillis();
        Long lastModified = fileModificationTimes.get(file.getAbsolutePath());

        // Check for rapid modifications (encryption in progress)
        if (lastModified != null && (currentTime - lastModified) < 1000) {
            System.err.println("RAPID FILE MODIFICATION: " + file.getAbsolutePath());
            // This could indicate encryption in progress
        }

        fileModificationTimes.put(file.getAbsolutePath(), currentTime);
        checkSuspiciousActivity(file, "MODIFIED");
    }

    private void onFileDeleted(File file) {
        fileModificationTimes.remove(file.getAbsolutePath());
        fileOriginalExtensions.remove(file.getAbsolutePath());
        checkSuspiciousActivity(file, "DELETED");
    }

    private void checkSuspiciousActivity(File file, String operation) {
        // Check for ransomware extensions
        String currentExtension = getFileExtension(file.getName());
        String originalExtension = fileOriginalExtensions.get(file.getAbsolutePath());

        if (originalExtension != null && !originalExtension.equals(currentExtension)) {
            // File extension changed - potential ransomware activity
            if (RansomwarePatterns.RANSOMWARE_EXTENSIONS.contains(currentExtension.toLowerCase())) {
                System.err.println("RANSOMWARE ALERT: File extension changed to known ransomware extension!");
                System.err.println("File: " + file.getAbsolutePath());
                System.err.println("Original: " + originalExtension + " -> New: " + currentExtension);

                // Take immediate action
                takeEmergencyAction(file);
            }
        }

        // Check for mass file operations
        if (isMassOperationDetected()) {
            System.err.println("MASS FILE OPERATION DETECTED - POSSIBLE RANSOMWARE ATTACK!");
        }
    }

    private boolean isMassOperationDetected() {
        long currentTime = System.currentTimeMillis();
        int rapidOperations = 0;

        // Count operations in last 5 seconds
        for (Long timestamp : fileModificationTimes.values()) {
            if (currentTime - timestamp < 5000) {
                rapidOperations++;
            }
        }

        return rapidOperations > 50; // Threshold for mass operations
    }

    private void takeEmergencyAction(File suspiciousFile) {
        System.err.println("EMERGENCY ACTION: Isolating suspicious file");

        // In a real implementation, you would:
        // 1. Quarantine the file
        // 2. Alert administrators
        // 3. Possibly disconnect from network
        // 4. Stop certain services

        try {
            // Example: Move to quarantine
            Path quarantineDir = Paths.get("C:\\Quarantine\\Ransomware");
            Files.createDirectories(quarantineDir);

            Path source = suspiciousFile.toPath();
            Path target = quarantineDir.resolve(suspiciousFile.getName());

            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
            System.err.println("File quarantined: " + target);

        } catch (Exception e) {
            System.err.println("Error quarantining file: " + e.getMessage());
        }
    }

    public void stopMonitoring() {
        isMonitoring = false;
        try {
            if (watchService != null) {
                watchService.close();
            }
        } catch (Exception e) {
            System.err.println("Error stopping monitoring: " + e.getMessage());
        }
    }

    private String getFileExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        return (lastDot == -1) ? "" : filename.substring(lastDot);
    }

    // Get monitoring statistics
    public Map<String, Object> getMonitoringStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("monitoredDirectories", new ArrayList<>(monitoredDirectories));
        stats.put("trackedFiles", fileModificationTimes.size());
        stats.put("isMonitoring", isMonitoring);
        return stats;
    }
}