package com.maksoud.filescanner.core;

import com.maksoud.filescanner.analyzer.model.FileAnalysisResult;
import com.maksoud.filescanner.analyzer.model.SecurityRisk;

public class RiskAssessor {

    public static SecurityRisk assessRiskLevel(int riskScore) {
        if (riskScore >= 80) {
            return SecurityRisk.CRITICAL;
        } else if (riskScore >= 60) {
            return SecurityRisk.HIGH;
        } else if (riskScore >= 40) {
            return SecurityRisk.MEDIUM;
        } else if (riskScore >= 20) {
            return SecurityRisk.LOW;
        } else {
            return SecurityRisk.LOW;
        }
    }

    public static boolean isImmediateActionRequired(FileAnalysisResult result) {
        return result.getRiskLevel() == SecurityRisk.CRITICAL ||
                (result.getRiskLevel() == SecurityRisk.HIGH &&
                        result.getWarnings().stream()
                                .anyMatch(w -> w.contains("ransomware") || w.contains("encryption")));
    }
}
