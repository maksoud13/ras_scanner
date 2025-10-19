package com.maksoud.filescanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
public class FilescannerApplication {

	@SpringBootApplication
	@EnableAsync
	@EnableScheduling
	public class SecurityAnalyzerApplication {
		public static void main(String[] args) {
			SpringApplication.run(SecurityAnalyzerApplication.class, args);
		}
	}
}
