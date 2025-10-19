package com.maksoud.filescanner.analyzer.service;

import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;
import com.maksoud.filescanner.analyzer.model.ScanResult;
import org.springframework.stereotype.Service;

import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

@Service
public class ReportService {

    public String generateHtmlReport(ScanResult scanResult) {
        StringBuilder html = new StringBuilder();
        
        html.append("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Analysis Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
                    .critical { color: #dc3545; font-weight: bold; }
                    .warning { color: #ffc107; font-weight: bold; }
                    .safe { color: #28a745; }
                    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                    th { background-color: #f8f9fa; }
                    .risk-high { background-color: #f8d7da; }
                    .risk-medium { background-color: #fff3cd; }
                    .risk-low { background-color: #d1ecf1; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Security Analysis Report</h1>
                    <p>Generated: %s</p>
                    <p>Scan Path: %s</p>
                    <p>Total Files: %d | Safe: %d | Suspicious: %d | Critical: %d</p>
                </div>
            """.formatted(
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()),
                scanResult.getScanPath(),
                scanResult.getTotalFilesScanned(),
                scanResult.getSafeFiles(),
                scanResult.getSuspiciousFiles(),
                scanResult.getCriticalFiles()
            ));
        
        // Add file results table
        html.append("""
            <h2>File Analysis Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>File Name</th>
                        <th>Risk Level</th>
                        <th>Risk Score</th>
                        <th>Safe</th>
                        <th>Warnings</th>
                    </tr>
                </thead>
                <tbody>
            """);
        
        for (FileAnalysisResult result : scanResult.getFileResults()) {
            String riskClass = getRiskClass(result.getRiskLevel().getName());
            html.append("""
                <tr class="%s">
                    <td>%s</td>
                    <td>%s</td>
                    <td>%d</td>
                    <td>%s</td>
                    <td>%s</td>
                </tr>
                """.formatted(
                    riskClass,
                    result.getFileName(),
                    result.getRiskLevel().getName(),
                    result.getRiskScore(),
                    result.isSafe() ? "Yes" : "No",
                    String.join(", ", result.getWarnings())
                ));
        }
        
        html.append("""
                </tbody>
            </table>
            </body>
            </html>
            """);
        
        return html.toString();
    }
    
    private String getRiskClass(String riskLevel) {
        return switch (riskLevel.toLowerCase()) {
            case "high", "critical" -> "risk-high";
            case "medium" -> "risk-medium";
            default -> "risk-low";
        };
    }
    
    public void saveReportToFile(ScanResult scanResult, String filename) {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(generateHtmlReport(scanResult));
        } catch (IOException e) {
            throw new RuntimeException("Failed to save report: " + e.getMessage(), e);
        }
    }
}
