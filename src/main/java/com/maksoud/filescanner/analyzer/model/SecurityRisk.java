package com.maksoud.filescanner.analyzer.model;

public enum SecurityRisk {
    LOW(0, "Low", "File appears safe", "#28a745"),
    MEDIUM(1, "Medium", "File has suspicious characteristics", "#ffc107"),
    HIGH(2, "High", "File is potentially dangerous", "#fd7e14"),
    CRITICAL(3, "Critical", "File is highly dangerous", "#dc3545");
    
    private final int level;
    private final String name;
    private final String description;
    private final String color;
    
    SecurityRisk(int level, String name, String description, String color) {
        this.level = level;
        this.name = name;
        this.description = description;
        this.color = color;
    }
    
    public int getLevel() { return level; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public String getColor() { return color; }
    
    public static SecurityRisk fromLevel(int level) {
        for (SecurityRisk risk : values()) {
            if (risk.getLevel() == level) {
                return risk;
            }
        }
        return LOW;
    }
    
    public static SecurityRisk fromName(String name) {
        for (SecurityRisk risk : values()) {
            if (risk.getName().equalsIgnoreCase(name)) {
                return risk;
            }
        }
        return LOW;
    }
    
    public boolean isHigherThan(SecurityRisk other) {
        return this.level > other.level;
    }
    
    public boolean isLowerThan(SecurityRisk other) {
        return this.level < other.level;
    }
}