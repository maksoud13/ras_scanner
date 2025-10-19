package com.maksoud.filescanner.analyzer.service;

import com.maksoud.filescanner.modules.ransomware.BehaviorMonitor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class FileMonitoringService {

    @Autowired
    private BehaviorMonitor behaviorMonitor;

    private Map<String, Boolean> monitoredDirectories = new HashMap<>();
    private Map<String, Long> alertCounts = new HashMap<>();

    public void startMonitoring(String directoryPath) {
        behaviorMonitor.startMonitoring(directoryPath);
        monitoredDirectories.put(directoryPath, true);
        alertCounts.put(directoryPath, 0L);
    }

    public void stopMonitoring(String directoryPath) {
        // Implementation to stop monitoring specific directory
        monitoredDirectories.put(directoryPath, false);
    }

    public Map<String, Object> getMonitoringStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("monitoredDirectories", monitoredDirectories);
        status.put("alertCounts", alertCounts);
        status.put("totalAlerts", alertCounts.values().stream().mapToLong(Long::longValue).sum());
        return status;
    }

    @Scheduled(fixedRate = 30000) // Run every 30 seconds
    public void checkSystemHealth() {
        // System health monitoring logic
        System.out.println("System health check performed at: " + System.currentTimeMillis());
    }

    public void recordAlert(String directoryPath) {
        alertCounts.put(directoryPath, alertCounts.getOrDefault(directoryPath, 0L) + 1);
    }
}