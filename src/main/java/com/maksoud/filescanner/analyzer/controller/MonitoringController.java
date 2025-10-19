package com.maksoud.filescanner.analyzer.controller;

import com.maksoud.filescanner.analyzer.model.ApiResponse;
import com.maksoud.filescanner.analyzer.service.ScheduledMonitorService;
import com.maksoud.filescanner.analyzer.service.FileMonitoringService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/monitoring")
@CrossOrigin(origins = "*")
public class MonitoringController {

    @Autowired
    private ScheduledMonitorService monitorService;


    @GetMapping("/status")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getMonitoringStatus() {
        try {
            Map<String, Object> status = new HashMap<>();
            status.put("alerts", monitorService.getAlertLog().size());
            status.put("lastScans", monitorService.getLastScanTimes());
            status.put("activeMonitoring", true);
            status.put("criticalPaths", Arrays.asList(
                    "C:\\Windows\\System32",
                    "C:\\Program Files",
                    "C:\\Users"));

            return ResponseEntity.ok(ApiResponse.success(status));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Failed to get monitoring status: " + e.getMessage()));
        }
    }

    @GetMapping("/alerts")
    public ResponseEntity<ApiResponse<List<String>>> getRecentAlerts() {
        try {
            List<String> alerts = monitorService.getAlertLog();
            // Return last 50 alerts
            int start = Math.max(0, alerts.size() - 50);
            List<String> recentAlerts = alerts.subList(start, alerts.size());

            return ResponseEntity.ok(ApiResponse.success(recentAlerts));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Failed to get alerts: " + e.getMessage()));
        }
    }

    @PostMapping("/start-system")
    public ResponseEntity<ApiResponse<String>> startSystemMonitoring() {
        try {
            // System monitoring starts automatically via @Scheduled
            return ResponseEntity.ok(
                    ApiResponse.success("System monitoring scheduler started", null));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Failed to start system monitoring: " + e.getMessage()));
        }
    }
}