package com.maksoud.filescanner.analyzer.controller;

import com.maksoud.filescanner.analyzer.model.ApiResponse;
import com.maksoud.filescanner.analyzer.model.ScanResult;
import com.maksoud.filescanner.analyzer.service.RansomwareDetectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/ransomware")
@CrossOrigin(origins = "*")
public class RansomwareController {

    @Autowired
    private RansomwareDetectionService ransomwareService;

    @PostMapping("/scan")
    public ResponseEntity<ApiResponse<ScanResult>> scanForRansomware(
            @RequestParam String directoryPath) {
        
        try {
            ScanResult result = ransomwareService.performRansomwareScan(directoryPath);
            
            if (result.isRansomwareDetected()) {
                return ResponseEntity.ok(
                    ApiResponse.success("🚨 RANSOMWARE DETECTED! Immediate action required!", result)
                );
            } else {
                return ResponseEntity.ok(
                    ApiResponse.success("No ransomware detected", result)
                );
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(ApiResponse.error("Ransomware scan failed: " + e.getMessage()));
        }
    }

    @PostMapping("/monitoring/start")
    public ResponseEntity<ApiResponse<String>> startMonitoring(
            @RequestParam String directoryPath) {
        
        try {
            ransomwareService.startRealTimeMonitoring(directoryPath);
            return ResponseEntity.ok(
                ApiResponse.success("Real-time monitoring started for: " + directoryPath, null)
            );
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(ApiResponse.error("Failed to start monitoring: " + e.getMessage()));
        }
    }

    @GetMapping("/monitoring/status")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getMonitoringStatus() {
        try {
            Map<String, Object> status = ransomwareService.getMonitoringStatus();
            return ResponseEntity.ok(ApiResponse.success(status));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(ApiResponse.error("Failed to get monitoring status: " + e.getMessage()));
        }
    }
}