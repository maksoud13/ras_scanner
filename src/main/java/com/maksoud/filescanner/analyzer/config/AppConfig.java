package com.maksoud.filescanner.analyzer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import com.maksoud.filescanner.core.SecurityScanner;
import com.maksoud.filescanner.modules.ransomware.RansomwareDetector;
import com.maksoud.filescanner.modules.ransomware.BehaviorMonitor;
import java.util.concurrent.Executor;

@Configuration
public class AppConfig {

@Bean
    public SecurityScanner securityScanner() {
        return new SecurityScanner();
    }

    @Bean
    public RansomwareDetector ransomwareDetector() {
        return new RansomwareDetector();
    }

    @Bean
    public BehaviorMonitor behaviorMonitor() {
        return new BehaviorMonitor();
    }

    @Bean
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(25);
        executor.setThreadNamePrefix("SecurityScan-");
        executor.initialize();
        return executor;
    }
}
