package com.maksoud.filescanner.analyzer.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.maksoud.filescanner.analyzer.config.AnalysisRequest;
import com.maksoud.filescanner.analyzer.model.ApiResponse;
import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;
import com.maksoud.filescanner.analyzer.model.ScanResult;
import com.maksoud.filescanner.analyzer.service.SecurityAnalysisService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/analysis")
@CrossOrigin(origins = "*")
public class AnalysisController {

    @Autowired
    private SecurityAnalysisService analysisService;

    @PostMapping("/file")
    public ResponseEntity<ApiResponse<FileAnalysisResult>> analyzeFile(
            @Valid @RequestBody AnalysisRequest request) {
        
        if (!analysisService.validatePath(request.getFilePath())) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("File path does not exist: " + request.getFilePath()));
        }
        
        String pathType = analysisService.getPathType(request.getFilePath());
        if (!"FILE".equals(pathType)) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Path is not a file: " + request.getFilePath()));
        }
        
        try {
            FileAnalysisResult result = analysisService.analyzeFile(request.getFilePath());
            return ResponseEntity.ok(ApiResponse.success("File analysis completed", result));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(ApiResponse.error("Analysis failed: " + e.getMessage()));
        }
    }

    @PostMapping("/directory")
    public ResponseEntity<ApiResponse<ScanResult>> analyzeDirectory(
            @Valid @RequestBody AnalysisRequest request) {
        
        if (!analysisService.validatePath(request.getFilePath())) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Directory path does not exist: " + request.getFilePath()));
        }
        
        String pathType = analysisService.getPathType(request.getFilePath());
        if (!"DIRECTORY".equals(pathType)) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Path is not a directory: " + request.getFilePath()));
        }
        
        try {
            ScanResult result = analysisService.analyzeDirectory(request.getFilePath());
            return ResponseEntity.ok(ApiResponse.success("Directory analysis completed", result));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(ApiResponse.error("Analysis failed: " + e.getMessage()));
        }
    }

    @GetMapping("/validate-path")
    public ResponseEntity<ApiResponse<Object>> validatePath(@RequestParam String path) {
        boolean exists = analysisService.validatePath(path);
        String type = analysisService.getPathType(path);
        
        var response = new java.util.HashMap<String, Object>();
        response.put("path", path);
        response.put("exists", exists);
        response.put("type", type);
        
        return ResponseEntity.ok(ApiResponse.success(response));
    }
}